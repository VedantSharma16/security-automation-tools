"""Minimal YAML-subset parser (block maps, block lists, scalars, comments).

Covers the shape of Sigma rules without needing PyYAML. Unsupported YAML
features (anchors, multi-line scalars, flow maps) raise YamlError instead of
being silently misparsed.
"""
from __future__ import annotations

import re
from typing import Any


class YamlError(ValueError):
    pass


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


def _scalar(text: str) -> Any:
    text = text.strip()
    if text == "":
        return None
    if text[0] in "&*!|>{":
        raise YamlError(f"unsupported YAML construct: {text!r}")
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise YamlError(f"unterminated string: {text!r}")
        return text[1:-1].replace("''", "'")
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise YamlError(f"unterminated string: {text!r}")
        return bytes(text[1:-1], "utf-8").decode("unicode_escape")
    if text[0] == "[":
        if text[-1] != "]":
            raise YamlError(f"unterminated flow list: {text!r}")
        inner = text[1:-1].strip()
        return [] if not inner else [_scalar(p) for p in _split_flow(inner)]
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", text):
        return int(text)
    if re.fullmatch(r"[-+]?\d*\.\d+", text):
        return float(text)
    return text


def _split_flow(inner: str) -> list[str]:
    parts, cur, quote = [], "", None
    for ch in inner:
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
    parts.append(cur)
    return parts


def _split_key(content: str) -> tuple[str, str] | None:
    """Split 'key: value' honouring quoted keys; None if not a mapping entry."""
    if content and content[0] in "'\"":
        end = content.find(content[0], 1)
        if end != -1 and content[end + 1 : end + 2] == ":":
            return content[1:end], content[end + 2 :]
        return None
    m = re.match(r"^([^:]+?):(?:\s+(.*))?$", content)
    if m and not content.startswith("- "):
        return m.group(1).strip(), m.group(2) or ""
    return None


def loads(text: str) -> Any:
    lines: list[tuple[int, str, int]] = []
    for no, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlError(f"line {no}: tabs are not allowed for indentation")
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip() or stripped.strip() in ("---", "..."):
            continue
        lines.append((len(stripped) - len(stripped.lstrip()), stripped.strip(), no))
    if not lines:
        return None
    value, pos = _block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise YamlError(f"line {lines[pos][2]}: unexpected indentation")
    return value


def _block(lines, pos, indent):
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _list(lines, pos, indent)
    return _map(lines, pos, indent)


def _map(lines, pos, indent):
    result: dict[str, Any] = {}
    while pos < len(lines):
        ind, content, no = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlError(f"line {no}: unexpected indentation")
        kv = _split_key(content)
        if kv is None:
            raise YamlError(f"line {no}: expected 'key: value', got {content!r}")
        key, rest = kv
        if key in result:
            raise YamlError(f"line {no}: duplicate key {key!r}")
        pos += 1
        if rest.strip():
            result[key] = _scalar(rest)
        elif pos < len(lines) and (
            lines[pos][0] > indent
            or (lines[pos][0] == indent and lines[pos][1].startswith("-"))
        ):
            result[key], pos = _block(lines, pos, lines[pos][0])
        else:
            result[key] = None
    return result, pos


def _list(lines, pos, indent):
    items: list[Any] = []
    while pos < len(lines):
        ind, content, no = lines[pos]
        if ind < indent or not (content.startswith("- ") or content == "-"):
            break
        if ind > indent:
            raise YamlError(f"line {no}: unexpected indentation")
        rest = content[1:].strip()
        pos += 1
        if not rest:
            if pos < len(lines) and lines[pos][0] > indent:
                val, pos = _block(lines, pos, lines[pos][0])
                items.append(val)
            else:
                items.append(None)
        elif _split_key(rest) and rest[0] not in "[":
            # inline map start: "- key: value" with sibling keys indented deeper
            child_indent = ind + 2
            lines.insert(pos, (child_indent, rest, no))  # in place: caller shares it
            val, pos = _map(lines, pos, child_indent)
            items.append(val)
        else:
            items.append(_scalar(rest))
    return items, pos
