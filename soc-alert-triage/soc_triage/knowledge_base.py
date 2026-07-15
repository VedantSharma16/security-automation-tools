"""Loads the local MITRE ATT&CK technique knowledge base used for retrieval."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class Technique:
    id: str
    name: str
    tactic: str
    description: str
    keywords: List[str]

    def corpus_text(self) -> str:
        return f"{self.name} {self.description} {' '.join(self.keywords)}"


def load_techniques(path: Path) -> List[Technique]:
    data = json.loads(Path(path).read_text())
    return [Technique(**item) for item in data]
