"""Envio de comunicados por e-mail (SMTP configurado em Parâmetros)."""

import mimetypes
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

SMTP_TIMEOUT_SECONDS = 20
SMTP_SECURITIES = ("starttls", "ssl", "none")
DEFAULT_PORTS = {"starttls": 587, "ssl": 465, "none": 25}
MAX_RECIPIENTS = 20
MAX_ATTACHMENTS = 10
MAX_ATTACHMENTS_BYTES = 20 * 1024 * 1024
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


def parse_recipients(value):
    """Aceita lista ou texto separado por vírgula, ponto e vírgula ou quebra de linha.
    Devolve (endereços únicos, inválidos)."""
    if isinstance(value, str):
        value = [value]
    # Cada item pode trazer vários endereços (ex.: multipart envia o campo como um texto só).
    value = [part for item in value or [] for part in re.split(r"[,;\s]+", str(item))]
    seen, valid, invalid = set(), [], []
    for item in value or []:
        address = str(item).strip()
        if not address or address.lower() in seen:
            continue
        seen.add(address.lower())
        (valid if EMAIL_RE.match(address) else invalid).append(address)
    return valid, invalid


def smtp_config_problem(settings):
    if not settings or not settings.smtp_host:
        return "SMTP não configurado: cadastre o servidor em Geral > Parâmetros."
    if not settings.smtp_from_email:
        return "E-mail remetente não configurado: cadastre em Geral > Parâmetros."
    return None


def with_signature(body, signature):
    signature = (signature or "").strip()
    body = body.rstrip()
    return f"{body}\n\n-- \n{signature}\n" if signature else f"{body}\n"


def describe_error(exc):
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "usuário ou senha do SMTP recusados"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "destinatário(s) recusado(s) pelo servidor"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "remetente recusado pelo servidor"
    if isinstance(exc, ssl.SSLError):
        return f"falha TLS ({exc.reason or exc})"
    return str(exc) or exc.__class__.__name__


def connect(settings):
    security = settings.smtp_security if settings.smtp_security in SMTP_SECURITIES else "starttls"
    port = settings.smtp_port or DEFAULT_PORTS[security]
    if security == "ssl":
        client = smtplib.SMTP_SSL(
            settings.smtp_host, port, timeout=SMTP_TIMEOUT_SECONDS, context=ssl.create_default_context()
        )
    else:
        client = smtplib.SMTP(settings.smtp_host, port, timeout=SMTP_TIMEOUT_SECONDS)
        if security == "starttls":
            client.starttls(context=ssl.create_default_context())
    if settings.smtp_user:
        client.login(settings.smtp_user, settings.smtp_password or "")
    return client


def test_connection(settings):
    """Conecta e autentica, sem enviar nada. Levanta exceção em caso de falha."""
    with connect(settings) as client:
        client.noop()


def send_email(settings, recipients, subject, body, attachments=()):
    """Envia o texto (já com a assinatura) para os destinatários, com os anexos
    [(nome, bytes)]. Levanta exceção em falha."""
    message = EmailMessage()
    message["From"] = formataddr((settings.smtp_from_name or "", settings.smtp_from_email))
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message["Message-ID"] = make_msgid(domain=settings.smtp_from_email.rsplit("@", 1)[-1])
    message.set_content(with_signature(body, settings.email_signature))
    for filename, data in attachments:
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if filename.endswith(".zone"):
            content_type = "text/plain"
        maintype, subtype = content_type.split("/", 1)
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    with connect(settings) as client:
        client.send_message(message)
