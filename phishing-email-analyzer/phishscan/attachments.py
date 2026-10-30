"""Attachment risk checks (static only; attachments are never opened or executed)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from email.message import Message
from pathlib import PurePosixPath

from .models import Finding

EXECUTABLE = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf",
              ".ps1", ".hta", ".jar", ".msi", ".lnk", ".iso", ".img", ".dll"}
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE = {".zip", ".rar", ".7z", ".gz", ".tar"}
_MAGIC = {b"MZ": "Windows PE executable", b"%PDF": "PDF", b"PK\x03\x04": "ZIP/OOXML", b"\x7fELF": "ELF executable"}


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    magic: str


def iter_attachments(msg: Message):
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            yield fn, part.get_content_type(), part.get_payload(decode=True) or b""


def analyze_attachments(msg: Message) -> tuple[list[AttachmentInfo], list[Finding]]:
    infos, findings = [], []
    for fn, ctype, data in iter_attachments(msg):
        magic = next((name for sig, name in _MAGIC.items() if data.startswith(sig)), "unknown")
        infos.append(AttachmentInfo(fn, ctype, len(data), hashlib.sha256(data).hexdigest(), magic))
        suffixes = [s.lower() for s in PurePosixPath(fn).suffixes]
        ext = suffixes[-1] if suffixes else ""
        if ext in EXECUTABLE:
            findings.append(Finding("attachment", "high", "Executable/script attachment", fn, "T1204.002"))
        elif ext in MACRO:
            findings.append(Finding("attachment", "high", "Macro-enabled Office attachment", fn, "T1204.002"))
        elif ext in ARCHIVE:
            findings.append(Finding("attachment", "low", "Archive attachment (contents not inspected)", fn, "T1027"))
        if len(suffixes) >= 2 and ext in EXECUTABLE | MACRO | ARCHIVE and suffixes[-2] in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
            findings.append(Finding("attachment", "high", "Double extension masquerading as a document", fn, "T1036.007"))
        if magic == "Windows PE executable" and ext not in EXECUTABLE:
            findings.append(Finding("attachment", "high", "File content is a PE executable but extension disagrees", fn, "T1036.008"))
    return infos, findings
