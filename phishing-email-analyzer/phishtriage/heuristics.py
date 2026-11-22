"""Loader for the tunable keyword/extension lists in data/heuristics.json."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def load() -> dict[str, list[str]]:
    with resources.files("phishtriage.data").joinpath("heuristics.json").open(encoding="utf-8") as fh:
        return json.load(fh)
