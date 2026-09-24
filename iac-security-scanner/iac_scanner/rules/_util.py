"""Small helpers shared by rule modules."""

from __future__ import annotations


def walk_leaves(value, path=()):
    """Recursively yield (dotted_path, leaf_value) for every scalar leaf in a
    JSON-like structure of nested dicts/lists. Used by rules that need to
    scan arbitrary resource attributes (e.g. secret detection)."""
    if isinstance(value, dict):
        for key, sub in value.items():
            yield from walk_leaves(sub, path + (str(key),))
    elif isinstance(value, list):
        for index, sub in enumerate(value):
            yield from walk_leaves(sub, path + (str(index),))
    else:
        yield ".".join(path), value
