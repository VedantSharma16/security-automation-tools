"""Minimal YAML-subset parser sufficient for Sigma rules.

Supports block mappings, block sequences, inline ``[a, b]`` lists, quoted and
plain scalars, ints/bools/null, comments and ``|`` literal blocks. Anchors,
flow mappings and multi-document streams are intentionally unsupported.
"""
from __future__ import annotations

import re


class YamlError(ValueError):
    pass


def _scalar(text: str):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), text[1:-1])
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(p) for p in _split_flow(inner)] if inner else []
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _split_flow(s: str) -> list[str]:
    parts, cur, quote = [], "", None
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            cur += ch
        elif ch == ",":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _split_key(content: str):
    """Split ``key: value`` honouring quoted keys. Returns (key, rest) or None."""
    if content[:1] in "'\"":
        q = content[0]
        end = content.find(q, 1)
        if end != -1 and content[end + 1:end + 2] == ":":
            return content[1:end], content[end + 2:].strip()
        return None
    m = re.match(r"([^:]+?):(?:\s+(.*))?$", content)
    if m:
        return m.group(1).strip(), (m.group(2) or "").strip()
    return None


def loads(text: str):
    lines = []
    raw = text.splitlines()
    i = 0
    while i < len(raw):
        line = raw[i]
        i += 1
        if line.strip() == "---":
            continue
        body = _strip_comment(line).rstrip()
        if not body.strip():
            continue
        indent = len(body) - len(body.lstrip(" "))
        if body[indent:indent + 1] == "\t":
            raise YamlError("tabs are not allowed for indentation")
        content = body.strip()
        if content.endswith("|") and (_split_key(content[:-1].rstrip()) or content.startswith("- ")):
            block, bi = [], None
            while i < len(raw):
                nxt = raw[i]
                if nxt.strip() and len(nxt) - len(nxt.lstrip(" ")) <= indent:
                    break
                if nxt.strip() and bi is None:
                    bi = len(nxt) - len(nxt.lstrip(" "))
                block.append(nxt[bi:] if bi is not None and nxt.strip() else "")
                i += 1
            content = content[:-1].rstrip() + " " + '"' + "\\n".join(block).rstrip("\\n").replace('"', '\\"') + '"'
        lines.append((indent, content))
    if not lines:
        return None
    value, pos = _parse(lines, 0, lines[0][0])
    if pos != len(lines):
        raise YamlError(f"unexpected content: {lines[pos][1]!r}")
    return value


def _parse(lines, pos, indent):
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _parse_seq(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_seq(lines, pos, indent):
    out = []
    while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1].startswith("- ") or lines[pos][1] == "-"):
        item = lines[pos][1][1:].strip()
        if not item:
            pos += 1
            if pos < len(lines) and lines[pos][0] > indent:
                val, pos = _parse(lines, pos, lines[pos][0])
            else:
                val = None
            out.append(val)
        elif _split_key(item) and item[:1] not in "[":
            # inline mapping start: rewrite as nested block at deeper indent
            sub_indent = indent + 2
            lines[pos] = (sub_indent, item)
            val, pos = _parse_map(lines, pos, sub_indent)
            out.append(val)
        else:
            out.append(_scalar(item))
            pos += 1
    return out, pos


def _parse_map(lines, pos, indent):
    out = {}
    while pos < len(lines) and lines[pos][0] == indent:
        content = lines[pos][1]
        kv = _split_key(content)
        if kv is None:
            raise YamlError(f"expected 'key: value', got {content!r}")
        key, rest = kv
        pos += 1
        if rest:
            out[key] = _scalar(rest)
        elif pos < len(lines) and (lines[pos][0] > indent or (lines[pos][0] == indent and lines[pos][1].startswith("-"))):
            out[key], pos = _parse(lines, pos, lines[pos][0])
        else:
            out[key] = None
    if pos < len(lines) and lines[pos][0] > indent:
        raise YamlError(f"bad indentation near {lines[pos][1]!r}")
    return out, pos
