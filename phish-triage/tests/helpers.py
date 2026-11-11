"""Builders for synthetic test emails."""

from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage


def make_email(
    *,
    from_="Alice <alice@example.org>",
    subject="Hello",
    text="Hi there.",
    html=None,
    auth="spf=pass; dkim=pass; dmarc=pass",
    reply_to=None,
    return_path=None,
    received="from mail.example.org (mail.example.org [198.51.100.7]) by mx.example.org; "
             "Mon, 09 Nov 2026 10:00:00 +0000",
    attachments=(),
) -> bytes:
    msg = EmailMessage()
    if return_path:
        msg["Return-Path"] = return_path
    if received:
        msg["Received"] = received
    if auth:
        msg["Authentication-Results"] = f"mx.example.org; {auth}"
    msg["From"] = from_
    msg["To"] = "bob@example.org"
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, payload in attachments:
        msg.add_attachment(payload, maintype="application", subtype="octet-stream", filename=filename)
    return bytes(msg)


def make_zip(files: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    if encrypted:
        # zipfile can't write encrypted archives; set the "encrypted" general-purpose
        # flag bit in every local and central directory header instead.
        for sig, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (i := data.find(sig, start)) != -1:
                data[i + flag_offset] |= 0x1
                start = i + 4
    return bytes(data)
