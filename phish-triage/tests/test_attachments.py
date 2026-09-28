from phishtriage.attachments import classify_attachment
from phishtriage.parser import Attachment


def test_flags_executable_extension():
    reasons = classify_attachment(Attachment("payload.exe", "application/octet-stream", 100))
    assert any("executable/script" in r for r in reasons)


def test_flags_macro_enabled_office_document():
    reasons = classify_attachment(
        Attachment("resume.docm", "application/vnd.ms-word.document.macroEnabled.12", 100)
    )
    assert any("macro-enabled" in r for r in reasons)


def test_flags_double_extension():
    reasons = classify_attachment(Attachment("invoice.pdf.exe", "application/octet-stream", 100))
    assert any("double extension" in r for r in reasons)


def test_flags_zero_byte_attachment():
    reasons = classify_attachment(Attachment("empty.pdf", "application/pdf", 0))
    assert any("zero-byte" in r for r in reasons)


def test_benign_pdf_is_clean():
    reasons = classify_attachment(Attachment("report.pdf", "application/pdf", 5000))
    assert reasons == []


def test_no_extension_is_not_double_extension_flagged():
    reasons = classify_attachment(Attachment("README", "text/plain", 100))
    assert reasons == []
