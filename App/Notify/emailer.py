import os, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from smtplib import SMTPServerDisconnected

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
FROM_EMAIL = os.environ.get("FROM_EMAIL")
TO_EMAILS = [e.strip() for e in os.environ.get("TO_EMAILS", "").split(",") if e.strip()]

def _smtp_client():
    if not (SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and FROM_EMAIL and TO_EMAILS):
        raise RuntimeError("SMTP or email env vars not fully set")
    context = ssl.create_default_context()
    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    server.ehlo()
    server.starttls(context=context)
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    return server

def send_email(subject: str, html_body: str, text_body: str = None, client=None):
    if not (SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and FROM_EMAIL and TO_EMAILS):
        raise RuntimeError("SMTP or email env vars not fully set")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = ", ".join(TO_EMAILS)

    if text_body is None:
        # basic plain text fallback
        import re
        text_body = re.sub('<[^<]+?>', '', html_body)

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        if client is None:
            with _smtp_client() as c:
                c.sendmail(FROM_EMAIL, TO_EMAILS, msg.as_string())
            return None
        else:
            client.sendmail(FROM_EMAIL, TO_EMAILS, msg.as_string())
            return client
    except SMTPServerDisconnected:
        # Reconnect once and retry
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
            new_client = _smtp_client()
            new_client.sendmail(FROM_EMAIL, TO_EMAILS, msg.as_string())
            return new_client
        else:
            raise
