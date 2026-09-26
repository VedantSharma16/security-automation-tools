"""A minimal, dependency-free YAML serializer for the rule dicts this project builds.

This is not a general-purpose YAML library -- it only needs to round-trip
the plain str/int/float/bool/list/dict shapes that a Sigma rule dict is made
of, so it avoids adding a `pyyaml` dependency for one small piece of output
formatting.
"""

from __future__ import annotations

from typing import Any

_UNQUOTED_SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")


def _needs_quoting(s: str) -> bool:
    if s == "":
        return True
    if any(c not in _UNQUOTED_SAFE_CHARS for c in s):
        return True
    if s[0] in "-?:,[]{}#&*!|>'\"%@` " or s[-1] == " ":
        return True
    if s.lower() in ("true", "false", "null", "yes", "no", "~"):
        return True
    if s[0].isdigit():
        return True  # looks numeric or IP/version-like; quote so it stays a string
    return False


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if _needs_quoting(text):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return text


def dump(obj: Any, indent: int = 0) -> str:
    """Render `obj` as a YAML document (or fragment, when called with indent > 0)."""
    pad = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            return f"{pad}{{}}\n"
        lines = []
        for key, value in obj.items():
            key_str = _scalar(key) if _needs_quoting(str(key)) else str(key)
            if isinstance(value, (dict, list)) and value:
                lines.append(f"{pad}{key_str}:")
                lines.append(dump(value, indent + 1))
            else:
                lines.append(f"{pad}{key_str}: {_render_empty_or_scalar(value)}")
        return "\n".join(lines) + ("\n" if not lines[-1].endswith("\n") else "")
    if isinstance(obj, list):
        if not obj:
            return f"{pad}[]\n"
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                rendered = dump(item, indent + 1).lstrip()
                lines.append(f"{pad}- {rendered}")
            else:
                lines.append(f"{pad}- {_render_empty_or_scalar(item)}")
        return "".join(l if l.endswith("\n") else l + "\n" for l in lines)
    return f"{pad}{_scalar(obj)}\n"


def _render_empty_or_scalar(value: Any) -> str:
    if value == {}:
        return "{}"
    if value == []:
        return "[]"
    return _scalar(value)
