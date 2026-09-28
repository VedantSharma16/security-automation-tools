"""Attachment-risk heuristics based on filename/extension alone.

No file contents are inspected (this tool never executes or opens attachment
payloads) -- these are the same fast, explainable checks a mail gateway or a
first-pass analyst triage applies: known-dangerous executable types,
macro-enabled Office formats, and double extensions used to disguise an
executable as a document.
"""

from __future__ import annotations

from .parser import Attachment

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".jar", ".lnk", ".chm", ".cpl",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".potm"}

# Common, harmless-looking extensions attackers like to precede a hidden
# executable extension with, e.g. "invoice.pdf.exe".
BENIGN_LOOKING_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".jpg", ".jpeg", ".png", ".zip", ".csv",
}


def _extensions(filename: str) -> list[str]:
    parts = filename.lower().split(".")
    return [f".{p}" for p in parts[1:]] if len(parts) > 1 else []


def classify_attachment(attachment: Attachment) -> list[str]:
    """Return a list of human-readable risk reasons for one attachment (empty if none)."""
    reasons: list[str] = []
    exts = _extensions(attachment.filename)
    if not exts:
        return reasons

    final_ext = exts[-1]
    if final_ext in DANGEROUS_EXTENSIONS:
        reasons.append(f"executable/script attachment ({final_ext})")
    if final_ext in MACRO_EXTENSIONS:
        reasons.append(f"macro-enabled Office document ({final_ext})")
    if len(exts) >= 2 and exts[-2] in BENIGN_LOOKING_EXTENSIONS and final_ext in DANGEROUS_EXTENSIONS:
        reasons.append(
            f"double extension disguising an executable as {exts[-2]} ({attachment.filename})"
        )
    if attachment.size_bytes == 0:
        reasons.append("zero-byte attachment (possible failed/placeholder payload)")
    return reasons
