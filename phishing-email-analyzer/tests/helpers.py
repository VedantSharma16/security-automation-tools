from email.message import EmailMessage
from pathlib import Path

from phishscope.parser import parse_bytes

FIXTURES = Path(__file__).parent / "fixtures"


def make_email(
    frm="Alice <alice@example.org>",
    subject="Hello",
    body="Just checking in.",
    html=None,
    auth="spf=pass; dkim=pass; dmarc=pass",
    reply_to=None,
    return_path=None,
    attachments=(),
    received=(),
):
    """Build and parse an in-memory message, so tests describe only what matters."""
    m = EmailMessage()
    if return_path:
        m["Return-Path"] = return_path
    for r in received:
        m["Received"] = r
    if auth is not None:
        m["Authentication-Results"] = f"mx.test; {auth}"
    m["From"] = frm
    m["To"] = "bob@acme-corp.com"
    if reply_to:
        m["Reply-To"] = reply_to
    m["Subject"] = subject
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return parse_bytes(bytes(m))
