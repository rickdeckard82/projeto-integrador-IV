"""Coleta IMAP com um servidor falso que imita as respostas do imaplib.
Só IPs de documentação e domínios .example."""

import hashlib
import imaplib
import json
from datetime import datetime
from pathlib import Path

import pytest

import app.abuse_services as abuse_services
import app.abuse_worker as abuse_worker
from app.abuse_imap import ImapCollectError, ImapConfig, ReadOnlyMailbox, _quote, collect
from app.abuse_services import (
    ManualSessionResolver,
    get_abuse_settings,
    get_session_resolver,
    message_key_for,
)
from app.models import AbuseIncident, AbuseMailboxState, AbuseMessage, CgnatRule, PublicationLock, db

MAILBOX = "INBOX"


class FakeIMAP:
    def __init__(self, messages, uidvalidity=1, fail_on=(), select_ok=True, dates=None):
        self.messages = dict(messages)
        # INTERNALDATE por UID; padrão: 14-Oct-2026 12:00:00 +0000.
        self.dates = dict(dates or {})
        self.uidvalidity = uidvalidity
        self.fail_on = set(fail_on)
        self.select_ok = select_ok
        self.calls = []
        self.logged_out = False

    def select(self, mailbox, readonly=False):
        self.calls.append(("select", mailbox, readonly))
        if not self.select_ok:
            return "NO", [b"Mailbox does not exist"]
        return "OK", [str(len(self.messages)).encode()]

    def response(self, code):
        return code, [str(self.uidvalidity).encode()]

    def uid(self, command, *args):
        self.calls.append(("uid", command) + args)
        if command == "SEARCH":
            start = int(args[1].split()[1].split(":")[0])
            uids = sorted(u for u in self.messages if u >= start)
            if not uids and self.messages:
                uids = [max(self.messages)]  # comportamento real de "n:*" (RFC 3501)
            return "OK", [b" ".join(str(u).encode() for u in uids)]
        if command == "FETCH" and args[1] == "(INTERNALDATE)":
            lines = []
            for seq, uid in enumerate(int(item) for item in args[0].split(",")):
                if uid in self.messages:
                    lines.append(f'{seq + 1} (UID {uid} INTERNALDATE "{self.date_of(uid)}")'.encode())
            return "OK", lines
        if command == "FETCH":
            uid = int(args[0])
            if uid in self.fail_on:
                raise imaplib.IMAP4.abort("conexão caiu")
            raw = self.messages[uid]
            head = f'{uid} (UID {uid} INTERNALDATE "{self.date_of(uid)}" BODY[] {{{len(raw)}}}'
            return "OK", [(head.encode(), raw), b")"]
        raise AssertionError(command)

    def date_of(self, uid):
        return self.dates.get(uid, "14-Oct-2026 12:00:00 +0000")

    def logout(self):
        self.logged_out = True


def csv_message(message_id="<m@soc.example>", ip="203.0.113.37", port=45380, subject="Incidents",
                when="2026-10-14T08:00:00+00:00"):
    headers = [
        "From: alerts@soc.example",
        "To: abuse@isp.example",
        f"Subject: {subject}",
        "Date: Wed, 14 Oct 2026 12:00:00 +0000",
    ]
    if message_id:
        headers.append(f"Message-ID: {message_id}")
    body = (
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nAttached.\n\n"
        '--B\nContent-Type: text/csv; name="e.csv"\nContent-Disposition: attachment; filename="e.csv"\n\n'
        f"timestamp,src_ip,src_port,type\n{when},{ip},{port},bruteforce\n--B--\n"
    )
    return ("\n".join(headers) + "\n" + body).encode()


@pytest.fixture
def ctx(app):
    with app.app_context():
        settings = get_abuse_settings()
        settings.own_prefixes = json.dumps(["203.0.113.0/24", "2001:db8:100::/48"])
        db.session.commit()
        yield app


def run(fake):
    return collect(ReadOnlyMailbox(fake, MAILBOX), MAILBOX)


def state():
    return AbuseMailboxState.query.filter_by(mailbox=MAILBOX).one()


# --- leitura somente ---------------------------------------------------------------

def test_mailbox_is_opened_readonly_and_fetch_uses_peek(ctx):
    fake = FakeIMAP({1: csv_message()})
    run(fake)
    assert ("select", MAILBOX, True) in fake.calls
    fetches = [call for call in fake.calls if call[:2] == ("uid", "FETCH")]
    assert fetches == [("uid", "FETCH", "1", "(INTERNALDATE BODY.PEEK[])")]
    assert not any(call[1] in ("STORE", "COPY", "MOVE", "EXPUNGE") for call in fake.calls if call[0] == "uid")


def test_select_failure_raises(ctx):
    with pytest.raises(ImapCollectError):
        ReadOnlyMailbox(FakeIMAP({}, select_ok=False), MAILBOX)


# --- UID incremental --------------------------------------------------------------

def test_incremental_uids(ctx):
    fake = FakeIMAP({1: csv_message("<a@x.example>"), 2: csv_message("<b@x.example>")}, uidvalidity=7)
    stats = run(fake)
    assert (stats.created, stats.duplicates, stats.last_uid) == (2, 0, 2)
    assert state().uidvalidity == 7 and state().last_uid == 2

    # Sem mensagens novas: o "3:*" do servidor devolve o UID 2, que não é reprocessado.
    stats = run(fake)
    assert (stats.fetched, stats.created) == (0, 0)

    fake.messages[3] = csv_message("<c@x.example>")
    stats = run(fake)
    assert (stats.fetched, stats.created, stats.last_uid) == (1, 1, 3)
    assert ("uid", "SEARCH", None, "UID 3:*") in fake.calls
    assert AbuseMessage.query.count() == 3


def test_uidvalidity_change_rescans_without_duplicates(ctx):
    run(FakeIMAP({1: csv_message("<a@x.example>"), 2: csv_message("<b@x.example>")}, uidvalidity=1))
    # Caixa recriada no servidor: UIDs renumerados e uma mensagem nova.
    fake = FakeIMAP(
        {10: csv_message("<a@x.example>"), 11: csv_message("<b@x.example>"), 12: csv_message("<c@x.example>")},
        uidvalidity=2,
    )
    stats = run(fake)
    assert stats.rescanned is True
    assert (stats.created, stats.duplicates, stats.last_uid) == (1, 2, 12)
    assert ("uid", "SEARCH", None, "UID 1:*") in fake.calls
    assert AbuseMessage.query.count() == 3
    assert state().uidvalidity == 2


# --- deduplicação ------------------------------------------------------------------

def test_duplicate_message_id_is_stored_once(ctx):
    raw = csv_message("<same@x.example>")
    other = csv_message("<same@x.example>", subject="Outro assunto")
    stats = run(FakeIMAP({1: raw, 2: other}))
    assert (stats.created, stats.duplicates, stats.last_uid) == (1, 1, 2)
    assert AbuseMessage.query.count() == 1


def test_message_id_is_normalized_for_dedup():
    assert message_key_for(b"x", "<ABC@X.example>") == message_key_for(b"y", " abc@x.example ")


def test_without_message_id_dedup_by_content(ctx):
    a = csv_message(message_id=None)
    b = csv_message(message_id=None, ip="203.0.113.38")
    stats = run(FakeIMAP({1: a, 2: a, 3: b}))
    assert (stats.created, stats.duplicates) == (2, 1)
    stored = AbuseMessage.query.order_by(AbuseMessage.id).all()
    assert stored[0].message_id is None
    assert stored[0].message_key == hashlib.sha256(b"raw:" + a).hexdigest()


# --- arquivo bruto -----------------------------------------------------------------

def test_raw_eml_is_saved_before_parse(ctx):
    raw = csv_message()
    run(FakeIMAP({5: raw}, uidvalidity=3))
    message = AbuseMessage.query.one()
    assert message.raw_path == f"abuse/2026/10/{hashlib.sha256(raw).hexdigest()}.eml"
    path = Path(ctx.config["UPLOAD_FOLDER"]) / message.raw_path
    assert path.read_bytes() == raw
    assert message.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert message.raw_size == len(raw)
    assert (message.imap_uidvalidity, message.imap_uid) == (3, 5)
    assert message.sender == "alerts@soc.example"
    assert message.sender_domain == "soc.example"
    assert message.received_at == datetime(2026, 10, 14, 12, 0, 0)


# --- falhas ------------------------------------------------------------------------

def test_failure_mid_batch_does_not_advance_uid(ctx):
    fake = FakeIMAP(
        {1: csv_message("<a@x.example>"), 2: csv_message("<b@x.example>"), 3: csv_message("<c@x.example>")},
        fail_on={2},
    )
    stats = run(fake)
    assert (stats.created, stats.last_uid) == (1, 1)
    assert "conexão caiu" in stats.failure
    assert "conexão caiu" in state().last_error
    assert AbuseMessage.query.count() == 1

    fake.fail_on.clear()
    stats = run(fake)
    assert (stats.created, stats.last_uid, stats.failure) == (2, 3, None)
    assert state().last_error is None


def test_parse_error_is_recorded_and_queue_continues(ctx, monkeypatch):
    real_parse = abuse_services.parse_message

    def flaky_parse(message, settings):
        if message.get("Subject") == "boom":
            raise ValueError("e-mail malformado")
        return real_parse(message, settings)

    monkeypatch.setattr(abuse_services, "parse_message", flaky_parse)
    stats = run(FakeIMAP({1: csv_message("<a@x.example>", subject="boom"), 2: csv_message("<b@x.example>")}))
    assert (stats.created, stats.errors, stats.last_uid) == (2, 1, 2)
    broken = AbuseMessage.query.filter_by(message_id="<a@x.example>").one()
    assert broken.status == "error"
    assert "e-mail malformado" in broken.error
    assert broken.raw_path  # o bruto fica guardado para análise
    assert AbuseMessage.query.filter_by(message_id="<b@x.example>").one().status == "processed"


def test_oversized_message_is_kept_but_not_parsed(ctx):
    stats = collect(ReadOnlyMailbox(FakeIMAP({1: csv_message()}), MAILBOX), MAILBOX, max_parse_bytes=100)
    message = AbuseMessage.query.one()
    assert (stats.errors, message.status) == (1, "error")
    assert "excede o limite" in message.error
    assert AbuseIncident.query.count() == 0


# --- incidentes e CGNAT -------------------------------------------------------------

def test_incident_gets_private_ip_from_cgnat_rule(ctx):
    rule = CgnatRule(
        private_prefix="100.64.0.0/19",
        public_prefix="203.0.113.0/24",
        ports_per_subscriber=2016,
        first_port=1024,
        allocation="interleaved",
        valid_from=datetime(2026, 1, 1),
    )
    db.session.add(rule)
    db.session.commit()
    stats = run(FakeIMAP({1: csv_message(ip="203.0.113.37", port=45380)}))
    assert stats.incidents == 1
    incident = AbuseIncident.query.one()
    assert incident.public_ip == "203.0.113.37"
    assert incident.source_port == 45380
    assert incident.occurred_at == datetime(2026, 10, 14, 8, 0, 0)
    assert incident.status == "new"
    assert incident.review_reasons is None
    assert incident.private_ip == "100.64.22.37"
    assert incident.cgnat_rule_id == rule.id


def test_incident_outside_cgnat_or_without_rule_has_no_private_ip(ctx):
    run(FakeIMAP({1: csv_message(ip="203.0.113.37", port=45380)}))
    incident = AbuseIncident.query.one()
    assert incident.private_ip is None and incident.cgnat_rule_id is None


def test_review_reasons_are_stored_as_json(ctx):
    run(FakeIMAP({1: csv_message(when="2026-10-14 08:00:00")}))  # sem fuso; soc.example sem fuso configurado
    incident = AbuseIncident.query.one()
    assert incident.status == "review"
    assert incident.occurred_at is None
    assert json.loads(incident.review_reasons) == ["Horário sem fuso e remetente sem fuso configurado"]


def test_message_with_only_third_party_ip_is_unrecognized(ctx):
    run(FakeIMAP({1: csv_message(ip="198.51.100.9")}))
    message = AbuseMessage.query.one()
    assert message.status == "unrecognized"
    assert message.parser == "csv"
    assert AbuseIncident.query.count() == 0


# --- worker ------------------------------------------------------------------------

def test_worker_run_once_logs_out_and_releases_lock(ctx, monkeypatch):
    fake = FakeIMAP({1: csv_message()})
    monkeypatch.setattr(abuse_worker, "connect", lambda config: fake)
    stats = abuse_worker.run_once(ctx, ImapConfig(host="imap.isp.example"), None)
    assert stats.created == 1
    assert fake.logged_out
    assert PublicationLock.query.get(abuse_worker.LOCK_NAME) is None


def test_worker_skips_when_lock_is_held(ctx, monkeypatch):
    db.session.add(PublicationLock(name=abuse_worker.LOCK_NAME, owner="outro", acquired_at=datetime.utcnow()))
    db.session.commit()
    monkeypatch.setattr(abuse_worker, "connect", lambda config: pytest.fail("não deveria conectar"))
    assert abuse_worker.run_once(ctx, ImapConfig(host="imap.isp.example"), None) is None


def test_worker_records_connection_error(ctx, monkeypatch):
    def refuse(config):
        raise ConnectionRefusedError("recusado")

    monkeypatch.setattr(abuse_worker, "connect", refuse)
    with pytest.raises(ConnectionRefusedError):
        abuse_worker.run_once(ctx, ImapConfig(host="imap.isp.example"), None)
    assert "recusado" in state().last_error
    assert PublicationLock.query.get(abuse_worker.LOCK_NAME) is None


def test_imap_config_from_settings():
    from app.models import ParameterSettings

    assert ImapConfig.from_settings(None) is None
    assert ImapConfig.from_settings(ParameterSettings(imap_host="  ")) is None
    config = ImapConfig.from_settings(
        ParameterSettings(imap_host="imap.isp.example", imap_user="abuse@isp.example", imap_password="segredo")
    )
    assert (config.host, config.port, config.mailbox) == ("imap.isp.example", 993, "INBOX")
    assert (config.user, config.password) == ("abuse@isp.example", "segredo")


def test_mailbox_name_quoting():
    assert _quote("INBOX") == "INBOX"
    assert _quote("INBOX.abuse") == "INBOX.abuse"
    assert _quote('Caixa "abuse"') == '"Caixa \\"abuse\\""'


# --- resolução de sessão -------------------------------------------------------------

def test_manual_session_resolver_returns_nothing(monkeypatch):
    monkeypatch.delenv("ABUSE_SESSION_RESOLVER", raising=False)
    resolver = get_session_resolver()
    assert isinstance(resolver, ManualSessionResolver)
    assert resolver.resolve("100.64.0.1", datetime(2026, 1, 1), datetime(2026, 1, 1, 0, 10)) == []


def test_unknown_session_resolver_is_rejected():
    with pytest.raises(ValueError):
        get_session_resolver("radacct")


# --- data de recebimento (INTERNALDATE) ----------------------------------------------

def broken_date_message(message_id="<spam@x.example>"):
    # Cabeçalho Date inválido, como no spam real que motivou a correção.
    return csv_message(message_id).replace(
        b"Date: Wed, 14 Oct 2026 12:00:00 +0000",
        b"Date: 2021-12-04 14:23:05.369466076 +0000 GMT m=+29332.865515324",
    )


def test_parse_internaldate():
    from app.abuse_imap import parse_internaldate

    assert parse_internaldate(b'1 (UID 9 INTERNALDATE "04-Dec-2021 11:23:05 -0300")') == datetime(2021, 12, 4, 14, 23, 5)
    assert parse_internaldate(b"1 (UID 9)") is None
    assert parse_internaldate(b'INTERNALDATE "lixo"') is None


def test_received_at_comes_from_internaldate(ctx):
    run(FakeIMAP({1: broken_date_message(), 2: csv_message()}, dates={1: "04-Dec-2021 11:23:05 -0300"}))
    spam = AbuseMessage.query.filter_by(imap_uid=1).one()
    assert spam.received_at == datetime(2021, 12, 4, 14, 23, 5)
    assert spam.raw_path.startswith("abuse/2021/12/")
    # Com INTERNALDATE, vale a chegada no servidor mesmo que o Date seja válido.
    assert AbuseMessage.query.filter_by(imap_uid=2).one().received_at == datetime(2026, 10, 14, 12, 0, 0)


def test_messages_without_date_are_backfilled_from_server(ctx):
    from app.abuse_services import ingest_raw_message

    # Gravadas por uma versão anterior: sem INTERNALDATE e com Date inválido.
    for uid in (1, 2):
        ingest_raw_message(broken_date_message(f"<old{uid}@x.example>"), uidvalidity=5, uid=uid)
    ingest_raw_message(broken_date_message("<other@x.example>"), uidvalidity=4, uid=1)
    db.session.commit()
    state_row = AbuseMailboxState(mailbox=MAILBOX, uidvalidity=5, last_uid=2)
    db.session.add(state_row)
    db.session.commit()

    fake = FakeIMAP(
        {1: b"", 2: b""},
        uidvalidity=5,
        dates={1: "04-Dec-2021 11:23:05 +0000", 2: "05-Dec-2021 08:00:00 +0000"},
    )
    stats = run(fake)
    assert stats.backfilled == 2
    assert ("uid", "FETCH", "1,2", "(INTERNALDATE)") in fake.calls
    dates = {m.message_id: m.received_at for m in AbuseMessage.query.all()}
    assert dates["<old1@x.example>"] == datetime(2021, 12, 4, 11, 23, 5)
    assert dates["<old2@x.example>"] == datetime(2021, 12, 5, 8, 0, 0)
    # UIDVALIDITY antigo: o UID não vale mais, então não é consultado.
    assert dates["<other@x.example>"] is None
