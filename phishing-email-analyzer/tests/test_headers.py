from phishscope.headers import originating_ip, parse_auth_results, parse_received_chain
from phishscope.parser import parse_bytes


def test_auth_results_failures(analyze):
    ctx, _, _ = analyze("credential_phish.eml")
    a = ctx.auth
    assert (a.spf, a.dkim, a.dmarc) == ("fail", "none", "fail")
    assert a.authserv_id == "mx.corp.example"
    assert a.spf_domain == "mailer.bulk-sender.xyz"


def test_auth_results_pass(analyze):
    ctx, _, _ = analyze("benign_notification.eml")
    assert (ctx.auth.spf, ctx.auth.dkim, ctx.auth.dmarc) == ("pass", "pass", "pass")
    assert ctx.auth.dkim_domains == ["github.com"]


def test_untrusted_authserv_is_ignored(make_eml):
    # Attacker pre-stamps a forged "all pass" header; only our MTA's ID is trusted.
    raw = make_eml({"Authentication-Results": "evil.example; spf=pass; dkim=pass; dmarc=pass"})
    email = parse_bytes(raw)
    assert parse_auth_results(email).dmarc == "pass"
    assert parse_auth_results(email, ["mx.corp.example"]).source == "absent"


def test_received_spf_fallback(make_eml):
    raw = make_eml({"Authentication-Results": None, "Received-SPF": "softfail (domain does not designate)"})
    a = parse_auth_results(parse_bytes(raw))
    assert a.spf == "softfail" and a.source == "received-spf"


def test_received_chain_order_and_origin(analyze):
    ctx, _, _ = analyze("credential_phish.eml")
    hops = ctx.hops
    assert len(hops) == 2
    assert hops[0].ip == "185.234.219.17"  # origin first
    assert hops[1].ip == "10.0.0.5"
    assert hops[1].delay_seconds == 3
    assert originating_ip(hops) == "185.234.219.17"


def test_origin_skips_private_addresses(make_eml):
    raw = make_eml({"Received": "from internal (internal [192.168.1.4]) by mx; Tue, 17 Nov 2026 09:00:00 +0000"})
    hops = parse_received_chain(parse_bytes(raw))
    assert hops[0].ip == "192.168.1.4"
    assert originating_ip(hops) == ""
