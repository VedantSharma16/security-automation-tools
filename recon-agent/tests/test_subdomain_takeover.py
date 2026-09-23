import struct

from recon_agent.subdomain_takeover import (
    TakeoverCandidate,
    build_cname_query,
    check_takeover,
    default_cname_lookup,
    parse_cname_response,
)


def _encode_name(name: str) -> bytes:
    labels = name.split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def _build_response(query_id: int, qname: str, *, ancount: int = 1, answer: bytes = b"", flags: int = 0x8180) -> bytes:
    header = struct.pack(">HHHHHH", query_id, flags, 1, ancount, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", 5, 1)
    return header + question + answer


class FakeUdpSocket:
    def __init__(self, response: bytes):
        self._response = response
        self.sent = None

    def settimeout(self, timeout):
        pass

    def sendto(self, data, addr):
        self.sent = (data, addr)

    def recvfrom(self, bufsize):
        return self._response, ("1.1.1.1", 53)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class TestBuildCnameQuery:
    def test_header_requests_recursion_for_a_single_cname_question(self):
        query, query_id = build_cname_query("example.com", query_id=0xABCD)
        assert query_id == 0xABCD
        qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", query[:12])
        assert (qid, flags, qdcount, ancount, nscount, arcount) == (0xABCD, 0x0100, 1, 0, 0, 0)

    def test_question_encodes_qtype_cname_and_class_in(self):
        query, _ = build_cname_query("sub.example.com", query_id=1)
        qtype, qclass = struct.unpack(">HH", query[-4:])
        assert (qtype, qclass) == (5, 1)

    def test_random_query_id_when_unspecified(self):
        _, query_id = build_cname_query("example.com")
        assert 0 <= query_id <= 0xFFFF


class TestParseCnameResponse:
    def test_parses_direct_cname_answer(self):
        cname_rdata = _encode_name("target.github.io")
        answer = _encode_name("sub.example.com") + struct.pack(">HHIH", 5, 1, 300, len(cname_rdata)) + cname_rdata
        packet = _build_response(0x1234, "sub.example.com", answer=answer)
        assert parse_cname_response(packet) == "target.github.io"

    def test_parses_cname_answer_whose_owner_name_is_compressed(self):
        # Real resolvers compress the answer's owner name into a pointer at
        # the question (the standard case) rather than repeating it.
        cname_rdata = _encode_name("target.github.io")
        pointer_to_question = struct.pack(">H", 0xC00C)  # offset 12 = start of question name
        answer = pointer_to_question + struct.pack(">HHIH", 5, 1, 300, len(cname_rdata)) + cname_rdata
        packet = _build_response(0x1234, "sub.example.com", answer=answer)
        assert parse_cname_response(packet) == "target.github.io"

    def test_parses_cname_rdata_that_is_itself_compressed(self):
        # rdata pointing back into the question name (e.g. a CNAME to a name
        # that shares a suffix already present earlier in the packet).
        pointer_rdata = struct.pack(">H", 0xC00C)
        answer = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 5, 1, 300, len(pointer_rdata)) + pointer_rdata
        packet = _build_response(0x1234, "sub.example.com", answer=answer)
        assert parse_cname_response(packet) == "sub.example.com"

    def test_nxdomain_with_no_answers_returns_none(self):
        packet = _build_response(0x1234, "nonexistent.example.com", ancount=0, flags=0x8183)
        assert parse_cname_response(packet) is None

    def test_answer_of_a_different_type_is_skipped(self):
        a_rdata = bytes([93, 184, 216, 34])
        answer = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 1, 1, 300, len(a_rdata)) + a_rdata  # type A, not CNAME
        packet = _build_response(0x1234, "sub.example.com", answer=answer)
        assert parse_cname_response(packet) is None

    def test_truncated_packet_returns_none_instead_of_raising(self):
        assert parse_cname_response(b"\x00\x01\x02") is None

    def test_pointer_loop_returns_none_instead_of_hanging(self):
        # A malicious/corrupt response whose only "name" is a pointer to itself.
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0)
        looping_name = struct.pack(">H", 0xC00C)  # points at offset 12, i.e. itself
        answer = looping_name + struct.pack(">HHIH", 5, 1, 300, 2) + looping_name
        packet = header + answer
        assert parse_cname_response(packet) is None


class TestDefaultCnameLookup:
    def test_returns_target_when_query_id_matches(self, monkeypatch):
        monkeypatch.setattr("recon_agent.subdomain_takeover.randint", lambda a, b: 0x1234)
        cname_rdata = _encode_name("target.github.io")
        answer = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 5, 1, 300, len(cname_rdata)) + cname_rdata
        response = _build_response(0x1234, "sub.example.com", answer=answer)
        monkeypatch.setattr("socket.socket", lambda *a, **k: FakeUdpSocket(response))

        assert default_cname_lookup("sub.example.com", timeout=1.0) == "target.github.io"

    def test_rejects_response_with_mismatched_query_id(self, monkeypatch):
        # Guards against off-path DNS spoofing / stale UDP responses.
        monkeypatch.setattr("recon_agent.subdomain_takeover.randint", lambda a, b: 0x1234)
        cname_rdata = _encode_name("target.github.io")
        answer = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 5, 1, 300, len(cname_rdata)) + cname_rdata
        response = _build_response(0x9999, "sub.example.com", answer=answer)  # wrong id
        monkeypatch.setattr("socket.socket", lambda *a, **k: FakeUdpSocket(response))

        assert default_cname_lookup("sub.example.com", timeout=1.0) is None


class TestCheckTakeover:
    def test_no_cname_record_is_not_vulnerable(self):
        candidate = check_takeover("www.example.com", cname_lookup=lambda h, t: None)
        assert candidate.vulnerable is False
        assert candidate.cname is None

    def test_cname_to_unrecognized_host_is_not_vulnerable(self):
        candidate = check_takeover("www.example.com", cname_lookup=lambda h, t: "internal.corp.local")
        assert candidate.vulnerable is False
        assert candidate.provider is None

    def test_fingerprint_match_in_response_body_is_vulnerable(self):
        candidate = check_takeover(
            "blog.example.com",
            cname_lookup=lambda h, t: "blog-example.github.io",
            body_fetcher=lambda url, t: (404, "<html>There isn't a GitHub Pages site here.</html>"),
        )
        assert candidate.vulnerable is True
        assert candidate.provider == "GitHub Pages"
        assert "github.io" in candidate.cname

    def test_live_claimed_resource_is_not_vulnerable(self):
        candidate = check_takeover(
            "blog.example.com",
            cname_lookup=lambda h, t: "blog-example.github.io",
            body_fetcher=lambda url, t: (200, "<html>Welcome to my real blog</html>"),
        )
        assert candidate.vulnerable is False

    def test_connection_failure_against_known_provider_is_treated_as_vulnerable(self):
        def failing_fetcher(url, timeout):
            raise OSError("Connection refused")

        candidate = check_takeover(
            "blog.example.com",
            cname_lookup=lambda h, t: "blog-example.github.io",
            body_fetcher=failing_fetcher,
        )
        assert candidate.vulnerable is True
        assert "Connection refused" in candidate.evidence

    def test_cname_lookup_failure_is_not_vulnerable(self):
        def failing_lookup(hostname, timeout):
            raise OSError("network unreachable")

        candidate = check_takeover("www.example.com", cname_lookup=failing_lookup)
        assert candidate.vulnerable is False
        assert "lookup failed" in candidate.evidence

    def test_matching_is_case_insensitive_and_suffix_based(self):
        candidate = check_takeover(
            "blog.example.com",
            cname_lookup=lambda h, t: "BLOG-EXAMPLE.GITHUB.IO",
            body_fetcher=lambda url, t: (404, "There isn't a GitHub Pages site here."),
        )
        assert candidate.provider == "GitHub Pages"
        assert candidate.vulnerable is True


def test_takeover_candidate_to_dict_roundtrip():
    candidate = TakeoverCandidate(
        subdomain="a.example.com",
        cname="a.example.com.github.io",
        provider="GitHub Pages",
        vulnerable=True,
        evidence="evidence text",
    )
    assert candidate.to_dict() == {
        "subdomain": "a.example.com",
        "cname": "a.example.com.github.io",
        "provider": "GitHub Pages",
        "vulnerable": True,
        "evidence": "evidence text",
    }
