"""Coleta da caixa de abuse por IMAPS, em modo somente leitura.

- ``SELECT`` com ``readonly=True`` e ``BODY.PEEK[]``: não marca como lida,
  não move e não apaga nada na caixa.
- Controle por UID: busca ``UID last_uid+1:*``. Se o UIDVALIDITY mudar, a
  caixa é varrida de novo; a deduplicação por Message-ID evita duplicatas.
- O UID só avança depois do commit da mensagem. Falha no meio do lote para a
  coleta; a próxima execução recomeça da primeira mensagem não gravada.
"""

import imaplib
import os
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from flask import current_app

from .abuse_services import ingest_raw_message
from .models import AbuseMailboxState, AbuseMessage, db

INTERNALDATE_RE = re.compile(rb'INTERNALDATE "([^"]+)"')
UID_RE = re.compile(rb"\bUID (\d+)")
BACKFILL_BATCH = 200


class ImapCollectError(RuntimeError):
    pass


@dataclass
class ImapConfig:
    host: str
    port: int = 993
    user: str = ""
    password: str = ""
    mailbox: str = "INBOX"
    ca_file: str | None = None
    timeout: int = 60

    @classmethod
    def from_settings(cls, settings):
        """Config da caixa de abuse cadastrada em Parâmetros; None = coleta desativada.
        CA própria e timeout continuam no .env (ajuste de infraestrutura)."""
        host = ((settings.imap_host if settings else None) or "").strip()
        if not host:
            return None
        return cls(
            host=host,
            port=settings.imap_port or 993,
            user=settings.imap_user or "",
            password=settings.imap_password or "",
            mailbox=settings.imap_mailbox or "INBOX",
            ca_file=os.getenv("ABUSE_IMAP_CA_FILE") or None,
            timeout=int(os.getenv("ABUSE_IMAP_TIMEOUT_SECONDS", "60")),
        )


def connect(config):
    """Abre a conexão TLS verificando o certificado (e o hostname)."""
    context = ssl.create_default_context(cafile=config.ca_file)
    connection = imaplib.IMAP4_SSL(
        config.host, config.port, ssl_context=context, timeout=config.timeout
    )
    connection.login(config.user, config.password)
    return connection


class ReadOnlyMailbox:
    """Fino invólucro sobre um ``imaplib.IMAP4`` já autenticado."""

    def __init__(self, connection, mailbox):
        self.connection = connection
        status, data = connection.select(_quote(mailbox), readonly=True)
        if status != "OK":
            raise ImapCollectError(f"Não foi possível abrir a caixa {mailbox!r}: {_text(data)}")
        _, validity = connection.response("UIDVALIDITY")
        try:
            self.uidvalidity = int(validity[0])
        except (TypeError, ValueError, IndexError) as exc:
            raise ImapCollectError("Servidor não informou UIDVALIDITY") from exc

    def uids_after(self, last_uid):
        status, data = self.connection.uid("SEARCH", None, f"UID {int(last_uid) + 1}:*")
        if status != "OK":
            raise ImapCollectError(f"Falha no UID SEARCH: {_text(data)}")
        uids = sorted({int(item) for item in b" ".join(data or [b""]).split()})
        # "n:*" com n acima do maior UID devolve o maior UID existente (RFC 3501).
        return [uid for uid in uids if uid > last_uid]

    def fetch(self, uid):
        """Corpo bruto e data de chegada no servidor (INTERNALDATE, UTC) de um UID."""
        status, data = self.connection.uid("FETCH", str(uid), "(INTERNALDATE BODY.PEEK[])")
        if status != "OK":
            raise ImapCollectError(f"Falha no UID FETCH {uid}: {_text(data)}")
        for item in data or []:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                return item[1], parse_internaldate(item[0])
        raise ImapCollectError(f"UID {uid} sem corpo na resposta do servidor")

    def internal_dates(self, uids):
        """{uid: INTERNALDATE em UTC} para vários UIDs, sem baixar o corpo."""
        if not uids:
            return {}
        status, data = self.connection.uid("FETCH", ",".join(str(uid) for uid in uids), "(INTERNALDATE)")
        if status != "OK":
            raise ImapCollectError(f"Falha no UID FETCH INTERNALDATE: {_text(data)}")
        result = {}
        for item in data or []:
            line = item[0] if isinstance(item, tuple) else item
            if not isinstance(line, bytes):
                continue
            uid_match = UID_RE.search(line)
            when = parse_internaldate(line)
            if uid_match and when:
                result[int(uid_match.group(1))] = when
        return result


def parse_internaldate(line):
    """'INTERNALDATE "04-Dec-2021 11:23:05 +0000"' -> datetime UTC sem fuso."""
    match = INTERNALDATE_RE.search(line or b"")
    if not match:
        return None
    try:
        value = datetime.strptime(match.group(1).decode("ascii").strip(), "%d-%b-%Y %H:%M:%S %z")
    except ValueError:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None)


@dataclass
class CollectStats:
    uidvalidity: int | None = None
    rescanned: bool = False
    fetched: int = 0
    created: int = 0
    duplicates: int = 0
    errors: int = 0
    incidents: int = 0
    last_uid: int = 0
    backfilled: int = 0
    failure: str | None = None
    created_ids: list = field(default_factory=list)


def collect(mailbox, mailbox_name, max_parse_bytes=None):
    """Processa as mensagens novas de ``mailbox`` (um ``ReadOnlyMailbox``)."""
    state = AbuseMailboxState.query.filter_by(mailbox=mailbox_name).first()
    if state is None:
        state = AbuseMailboxState(mailbox=mailbox_name, last_uid=0)
        db.session.add(state)
        db.session.commit()

    stats = CollectStats(uidvalidity=mailbox.uidvalidity)
    if state.uidvalidity != mailbox.uidvalidity:
        stats.rescanned = state.uidvalidity is not None
        state.uidvalidity = mailbox.uidvalidity
        state.last_uid = 0
        db.session.commit()

    try:
        for uid in mailbox.uids_after(state.last_uid):
            raw, internal_date = mailbox.fetch(uid)
            stats.fetched += 1
            outcome = ingest_raw_message(
                raw,
                uidvalidity=mailbox.uidvalidity,
                uid=uid,
                max_parse_bytes=max_parse_bytes,
                internal_date=internal_date,
            )
            state.last_uid = uid
            db.session.commit()
            if outcome.created:
                stats.created += 1
                stats.created_ids.append(outcome.message.id)
                if outcome.message.status == "error":
                    stats.errors += 1
                stats.incidents += outcome.incident_count
            else:
                stats.duplicates += 1
    except Exception as exc:
        db.session.rollback()
        stats.failure = f"{type(exc).__name__}: {exc}"[:2000]
        current_app.logger.exception("Coleta IMAP interrompida em %s", mailbox_name)

    if stats.failure is None:
        try:
            stats.backfilled = backfill_received_at(mailbox)
        except Exception as exc:  # só complementa datas; não invalida a coleta
            db.session.rollback()
            current_app.logger.warning("Não foi possível completar datas de recebimento: %s", exc)

    state = AbuseMailboxState.query.filter_by(mailbox=mailbox_name).first()
    state.last_run_at = datetime.utcnow()
    state.last_error = stats.failure
    db.session.commit()
    stats.last_uid = state.last_uid
    return stats


def backfill_received_at(mailbox, limit=BACKFILL_BATCH):
    """Completa a data de recebimento de mensagens gravadas sem ela.

    Mensagens coletadas antes desta versão (ou com cabeçalho Date inválido)
    ficaram sem data; o INTERNALDATE do servidor é a mesma data que o webmail
    mostra. Só vale para o UIDVALIDITY atual, em que o UID ainda é válido.
    """
    pending = (
        AbuseMessage.query.filter(
            AbuseMessage.received_at.is_(None),
            AbuseMessage.imap_uidvalidity == mailbox.uidvalidity,
            AbuseMessage.imap_uid.isnot(None),
        )
        .order_by(AbuseMessage.imap_uid)
        .limit(limit)
        .all()
    )
    if not pending:
        return 0
    dates = mailbox.internal_dates([message.imap_uid for message in pending])
    filled = 0
    for message in pending:
        when = dates.get(message.imap_uid)
        if when is not None:
            message.received_at = when
            filled += 1
    db.session.commit()
    return filled


def _quote(mailbox):
    if re.fullmatch(r"[A-Za-z0-9._/-]+", mailbox):
        return mailbox
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _text(data):
    return b" ".join(item for item in (data or []) if isinstance(item, bytes)).decode(errors="replace")
