"""Builds a manifest of evidence files for a case directory.

A "case" is just a directory of evidence dropped there by an analyst: an
auth log, an alert/report text file, maybe both, maybe neither. `load_case`
classifies each file so the planner (deterministic or LLM-driven) knows
which specialist tool a file is meant for, without hardcoding filenames.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

LOG_EXTENSIONS = {".log"}
ALERT_EXTENSIONS = {".txt", ".md"}
DESCRIPTION_FILENAME = "description.txt"


@dataclass(frozen=True)
class EvidenceFile:
    path: Path
    kind: str  # "log" | "alert" | "other"

    def to_dict(self) -> dict:
        return {"path": str(self.path), "kind": self.kind}


@dataclass(frozen=True)
class CaseManifest:
    case_dir: Path
    incident_description: str
    files: list[EvidenceFile]

    def files_of_kind(self, kind: str) -> list[EvidenceFile]:
        return [f for f in self.files if f.kind == kind]

    def to_dict(self) -> dict:
        return {
            "case_dir": str(self.case_dir),
            "incident_description": self.incident_description,
            "files": [f.to_dict() for f in self.files],
        }


def _classify(path: Path) -> str:
    name = path.name.lower()
    if path.suffix.lower() in LOG_EXTENSIONS or "log" in name:
        return "log"
    if path.suffix.lower() in ALERT_EXTENSIONS:
        return "alert"
    return "other"


def load_case(case_dir: str | Path, incident_description: str = "") -> CaseManifest:
    """Scan a case directory and classify each evidence file.

    A `description.txt` in the case directory is used as the incident
    description when the caller didn't pass one explicitly, and is excluded
    from the evidence file list.
    """
    case_dir = Path(case_dir)
    if not case_dir.is_dir():
        raise FileNotFoundError(f"case directory not found: {case_dir}")

    description = incident_description
    description_path = case_dir / DESCRIPTION_FILENAME
    if not description and description_path.is_file():
        description = description_path.read_text(encoding="utf-8").strip()

    files = [
        EvidenceFile(path=path, kind=_classify(path))
        for path in sorted(case_dir.iterdir())
        if path.is_file() and path.name != DESCRIPTION_FILENAME
    ]

    return CaseManifest(case_dir=case_dir, incident_description=description, files=files)
