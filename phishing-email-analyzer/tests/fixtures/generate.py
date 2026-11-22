"""Regenerate the synthetic .eml fixtures used by the test suite and README demos.

All domains, people and payloads are fictitious. The "malware" attachment is
just the two bytes 'MZ' plus filler text - it is not executable.

    python tests/fixtures/generate.py
"""

from __future__ import annotations

import base64
from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).parent


def base(subject, from_, auth, return_path, to="alex.morgan@example.org", reply_to=None):
    msg = EmailMessage()
    msg["Return-Path"] = return_path
    msg["Received"] = "from mx.sender.invalid (unknown [203.0.113.45]) by mx.example.org; Mon, 16 Nov 2026 09:12:03 +0000"
    msg["Authentication-Results"] = f"mx.example.org; {auth}"
    msg["From"] = from_
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 16 Nov 2026 09:12:01 +0000"
    msg["Message-ID"] = f"<{abs(hash(subject)) % 10**10}@fixture.invalid>"
    return msg


def credential_phish():
    msg = base(
        "Action required: unusual sign-in activity on your account",
        '"PayPal Security" <service@paypa1.com>',
        "spf=fail smtp.mailfrom=paypa1.com; dkim=none; dmarc=fail header.from=paypa1.com",
        "<bounce@mailer-7781.xyz>",
    )
    msg.set_content(
        "We detected unusual activity on your account. Verify your account within 24 hours "
        "or your account will be suspended. Sign in: https://www.paypal.com/signin"
    )
    msg.add_alternative(
        """<html><body>
<p>Dear customer,</p>
<p>We detected <b>unusual activity</b> on your account. To avoid suspension you must
<b>verify your account within 24 hours</b>, or your account will be suspended.</p>
<p><a href="http://paypal.com.account-verify.xyz/signin?id=88213">https://www.paypal.com/signin</a></p>
<p>Alternatively, <a href="https://bit.ly/3xPpL0g">log in here</a>.</p>
<p>PayPal Security Team</p>
</body></html>""",
        subtype="html",
    )
    return msg


def bec_invoice():
    msg = base(
        "Re: outstanding invoice - updated banking details",
        '"Sarah Chen (CFO)" <sarah.chen@acme-corp.com>',
        "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass",
        "<sarah.chen@acme-corp.com>",
        reply_to="sarah.chen.cfo@gmail.com",
    )
    msg.set_content(
        "Hi Alex,\n\nAre you at your desk? Our supplier has a new bank account and the "
        "outstanding invoice needs an urgent payment today via wire transfer. I'll send the "
        "updated banking details shortly. Please keep this confidential until the audit "
        "is complete.\n\nSarah"
    )
    return msg


def malware_attachment():
    msg = base(
        "DHL: Your parcel is on hold - invoice attached",
        '"DHL Express" <noreply@dhl-delivery-notice.top>',
        "spf=softfail smtp.mailfrom=dhl-delivery-notice.top; dkim=none; dmarc=none",
        "<noreply@dhl-delivery-notice.top>",
    )
    msg.set_content(
        "Your parcel could not be delivered. Open the invoice attached immediately to "
        "schedule redelivery. The archive password is 4471."
    )
    msg.add_attachment(b"MZ" + b"\x90" * 14 + b"not a real executable - test fixture",
                       maintype="application", subtype="octet-stream",
                       filename="Invoice_8812.pdf.exe")
    msg.add_attachment(b"PK\x03\x04" + b"\x00" * 26 + b"fixture", maintype="application",
                       subtype="zip", filename="shipping_docs.zip")
    return msg


def html_smuggling():
    msg = base(
        "Please DocuSign: Q4 contract",
        '"DocuSign via Partner Portal" <notifications@partner-portal.example.net>',
        "spf=pass smtp.mailfrom=partner-portal.example.net; dkim=pass; dmarc=pass",
        "<notifications@partner-portal.example.net>",
    )
    msg.set_content("A document is waiting for your signature. Open the attached secure message.")
    blob = base64.b64encode(b"fixture-payload").decode()
    smuggler = f"""<html><body><script>
var d = atob("{blob}");
var b = new Blob([d], {{type: "application/octet-stream"}});
var a = document.createElement("a");
a.href = URL.createObjectURL(b);
a.download = "Contract_Q4.iso";
a.click();
</script></body></html>"""
    msg.add_attachment(smuggler.encode(), maintype="text", subtype="html",
                       filename="Secure_Message.html")
    return msg


def benign_newsletter():
    msg = base(
        "Your weekly digest",
        '"GitHub" <noreply@github.com>',
        "spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com",
        "<bounces+123@github.com>",
    )
    msg.set_content("Here are the repositories trending this week: https://github.com/trending")
    msg.add_alternative(
        '<html><body><p>Trending this week:</p>'
        '<p><a href="https://github.com/trending">github.com/trending</a></p>'
        '<p><a href="https://github.com/settings/notifications">Notification settings</a></p>'
        "</body></html>",
        subtype="html",
    )
    return msg


FIXTURES = {
    "credential_phish.eml": credential_phish,
    "bec_invoice.eml": bec_invoice,
    "malware_attachment.eml": malware_attachment,
    "html_smuggling.eml": html_smuggling,
    "benign_newsletter.eml": benign_newsletter,
}

if __name__ == "__main__":
    for name, builder in FIXTURES.items():
        (HERE / name).write_bytes(bytes(builder()))
        print(f"wrote {name}")
