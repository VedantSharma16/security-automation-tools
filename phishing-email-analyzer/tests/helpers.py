from email.message import EmailMessage

from phishtriage.parser import ParsedEmail, parse_bytes


def make_email(*, from_="Alice <alice@example.com>", subject="Hello", text="hi", html=None,
               auth="spf=pass; dkim=pass; dmarc=pass", reply_to=None, return_path=None,
               attachments=()) -> ParsedEmail:
    msg = EmailMessage()
    if return_path:
        msg["Return-Path"] = return_path
    if auth is not None:
        msg["Authentication-Results"] = f"mx.test; {auth}"
    msg["From"] = from_
    msg["To"] = "bob@example.org"
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, data, (maintype, subtype) in attachments:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return parse_bytes(bytes(msg))
