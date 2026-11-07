"""Serviços do módulo de abuse que tocam o banco e o disco."""

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from email import message_from_bytes, policy
from pathlib import Path

from flask import current_app

from .abuse_parsers import ParserSettings, header_date, message_sender, parse_message
from .cgnat import CgnatRuleConflict, plan_rule_insertion, public_to_private
from .models import AbuseIncident, AbuseMessage, AbuseSettings, CgnatRule, db

DEFAULT_SENDER_TIMEZONES = {
    # Shadowserver documenta que todos os horários dos relatórios são UTC.
    "shadowserver.org": "UTC",
}


# --- configuração -----------------------------------------------------------------

def get_abuse_settings():
    settings = AbuseSettings.query.order_by(AbuseSettings.id).first()
    if settings is None:
        settings = AbuseSettings(
            own_prefixes=json.dumps([]),
            sender_timezones=json.dumps(DEFAULT_SENDER_TIMEZONES),
        )
        db.session.add(settings)
        db.session.commit()
    return settings


def parser_settings_from(settings):
    return ParserSettings(
        own_prefixes=_json(settings.own_prefixes, list),
        sender_timezones=_json(settings.sender_timezones, dict),
    )


def _json(value, kind):
    try:
        loaded = json.loads(value) if value else kind()
    except json.JSONDecodeError:
        return kind()
    return loaded if isinstance(loaded, kind) else kind()


# --- gravação de mensagens --------------------------------------------------------

@dataclass
class StoreOutcome:
    message: AbuseMessage | None
    created: bool
    incident_count: int = 0


def message_key_for(raw, message_id):
    normalized = (message_id or "").strip().strip("<>").strip().lower()
    source = f"message-id:{normalized}".encode() if normalized else b"raw:" + raw
    return hashlib.sha256(source).hexdigest()


def store_raw_message(raw, received_at=None):
    """Grava o .eml bruto em UPLOAD_FOLDER/abuse/AAAA/MM/<sha256>.eml.

    Retorna (caminho relativo ao UPLOAD_FOLDER, sha256). Escrita atômica; um
    arquivo já existente com o mesmo hash é reaproveitado.
    """
    digest = hashlib.sha256(raw).hexdigest()
    when = received_at or datetime.utcnow()
    relative = Path("abuse") / f"{when:%Y}" / f"{when:%m}" / f"{digest}.eml"
    target = Path(current_app.config["UPLOAD_FOLDER"]) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        temporary = target.with_suffix(".tmp")
        with open(temporary, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, target)
    return relative.as_posix(), digest


def ingest_raw_message(raw, uidvalidity=None, uid=None, max_parse_bytes=None, internal_date=None):
    """Registra uma mensagem bruta: dedup, .eml em disco, parse e incidentes.

    Não faz commit; quem chama decide (o coletor commita junto com o UID).
    Mensagem já conhecida (mesmo Message-ID, ou mesmo conteúdo sem Message-ID)
    não é duplicada.
    """
    message = message_from_bytes(raw, policy=policy.compat32)
    message_id = (message.get("Message-ID") or "").strip() or None
    key = message_key_for(raw, message_id)
    existing = AbuseMessage.query.filter_by(message_key=key).first()
    if existing is not None:
        return StoreOutcome(existing, False)

    record = AbuseMessage(
        message_id=message_id[:2000] if message_id else None,
        message_key=key,
        imap_uidvalidity=uidvalidity,
        imap_uid=uid,
        raw_size=len(raw),
    )
    _fill_headers(record, message)
    # "Recebida em" = chegada no servidor (o que o webmail mostra); o cabeçalho
    # Date é do remetente e pode vir ausente, inválido ou falso (spam).
    if internal_date is not None:
        record.received_at = internal_date
    record.raw_path, record.raw_sha256 = store_raw_message(raw, record.received_at)
    db.session.add(record)
    db.session.flush()

    if max_parse_bytes and len(raw) > max_parse_bytes:
        record.status = "error"
        record.error = f"Mensagem com {len(raw)} bytes excede o limite de leitura"
        return StoreOutcome(record, True)

    try:
        result = parse_message(message, parser_settings_from(get_abuse_settings()))
    except Exception as exc:  # um e-mail malformado não pode travar a fila
        current_app.logger.exception("Falha ao interpretar a mensagem de abuse %s", record.id)
        record.status = "error"
        record.parser = None
        record.error = f"{type(exc).__name__}: {exc}"[:2000]
        return StoreOutcome(record, True)

    record.parser = result.parser
    record.status = result.status
    if result.notes:
        record.error = "; ".join(result.notes)
    rules = CgnatRule.query.all()
    for data in result.incidents:
        db.session.add(_incident_from(record, data, rules))
    return StoreOutcome(record, True, len(result.incidents))


def _fill_headers(record, message):
    record.sender = (message_sender(message) or "")[:320] or None
    if record.sender and "@" in record.sender:
        record.sender_domain = record.sender.rpartition("@")[2].lower()[:253]
    subject = message.get("Subject")
    record.subject = str(subject)[:2000] if subject is not None else None
    record.received_at = header_date(message.get("Date"))


def _incident_from(record, data, rules):
    incident = AbuseIncident(
        abuse_message_id=record.id,
        public_ip=data.public_ip,
        source_port=data.source_port,
        destination_ip=data.destination_ip,
        destination_port=data.destination_port,
        occurred_at=data.occurred_at,
        occurred_at_raw=data.occurred_at_raw,
        timezone_used=data.timezone_used,
        timezone_assumed=data.timezone_assumed,
        incident_type=data.incident_type,
        raw_type=data.raw_type[:120] if data.raw_type else None,
        status=data.status,
        review_reasons=json.dumps(data.review_reasons, ensure_ascii=False) if data.review_reasons else None,
    )
    apply_cgnat(incident, rules)
    return incident


def apply_cgnat(incident, rules):
    """Calcula o IP privado do incidente. Sem porta de origem ou horário, não calcula."""
    incident.private_ip = None
    incident.cgnat_rule_id = None
    if incident.source_port is None or incident.occurred_at is None:
        return
    try:
        mapping = public_to_private(incident.public_ip, incident.source_port, incident.occurred_at, rules)
    except CgnatRuleConflict:
        current_app.logger.error("Regras de CGNAT sobrepostas para %s", incident.public_ip)
        return
    if mapping is not None:
        incident.private_ip = mapping.private_ip
        incident.cgnat_rule_id = getattr(mapping.rule, "id", None)


# --- resolução de sessão (IP privado -> login PPPoE) ------------------------------

@dataclass(frozen=True)
class SessionMatch:
    login: str
    session_start: datetime | None
    session_end: datetime | None
    source: str


class SessionResolver:
    """Contrato para descobrir o login PPPoE que usava um IP privado.

    ``resolve`` recebe o IP privado e a janela [start_utc, end_utc] e devolve
    as sessões que tocam a janela. Implementações futuras (ex.: radacct do
    FreeRADIUS) entram aqui sem mudar as rotas.
    """

    name = "base"

    def resolve(self, private_ip, start_utc, end_utc):
        raise NotImplementedError


class ManualSessionResolver(SessionResolver):
    """Nesta fase o operador consulta o BNG/RADIUS e preenche o login à mão."""

    name = "manual"

    def resolve(self, private_ip, start_utc, end_utc):
        return []


SESSION_RESOLVERS = {ManualSessionResolver.name: ManualSessionResolver}


def get_session_resolver(name=None):
    name = (name or os.getenv("ABUSE_SESSION_RESOLVER") or "manual").strip().lower()
    if name not in SESSION_RESOLVERS:
        raise ValueError(f"ABUSE_SESSION_RESOLVER desconhecido: {name!r}")
    return SESSION_RESOLVERS[name]()



# --- regras de CGNAT -------------------------------------------------------------

@dataclass
class CgnatImportPlan:
    group: str
    rules: list  # CgnatRule ainda não gravadas
    closings: list  # [(regra existente, novo valid_to)]
    pools: list  # ImportedPool, na ordem dos arquivos


def plan_cgnat_import(files, valid_from, valid_to=None, notes=None, user_id=None):
    """Lê os arquivos do A10 e monta as regras novas, sem gravar.

    ``files`` é uma lista de (nome, bytes). Lança ``CgnatImportError`` (arquivo
    ilegível), ``CgnatRuleError`` ou ``CgnatRuleConflict`` (vigência).
    """
    from .cgnat_import import CgnatImportError, parse_a10_fixed_nat

    if not files:
        raise CgnatImportError("Envie ao menos um arquivo de fixed-nat")
    group = str(uuid.uuid4())
    rules, pools = [], []
    for filename, content in files:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        try:
            pool = parse_a10_fixed_nat(text)
        except CgnatImportError as exc:
            raise CgnatImportError(f"{filename}: {exc}") from exc
        pools.append(pool)
        rules.append(
            CgnatRule(
                private_prefix=pool.private_prefix,
                public_prefix=pool.public_prefix,
                ports_per_subscriber=pool.ports_per_subscriber,
                first_port=pool.first_port,
                allocation=pool.allocation,
                valid_from=valid_from,
                valid_to=valid_to,
                pool_name=pool.pool_name,
                import_group=group,
                source_filename=(filename or "")[:255] or None,
                source_md5=pool.md5,
                notes=notes,
                created_by_user_id=user_id,
            )
        )
    closings = plan_rule_insertion(CgnatRule.query.all(), rules)
    return CgnatImportPlan(group=group, rules=rules, closings=closings, pools=pools)


def plan_manual_rule(values, user_id=None):
    group = str(uuid.uuid4())
    rule = CgnatRule(import_group=group, created_by_user_id=user_id, **values)
    closings = plan_rule_insertion(CgnatRule.query.all(), [rule])
    return CgnatImportPlan(group=group, rules=[rule], closings=closings, pools=[])


def apply_cgnat_plan(plan):
    for old, new_valid_to in plan.closings:
        old.valid_to = new_valid_to
        old.closed_by_group = plan.group
    for rule in plan.rules:
        db.session.add(rule)
    db.session.flush()
    return recompute_private_ips()


def delete_cgnat_group(group):
    """Apaga uma importação e reabre as regras que ela tinha encerrado.

    Só a importação mais recente de cada pool pode ser apagada: se alguma regra
    do grupo já foi encerrada por outra importação, a exclusão é recusada.
    """
    rules = CgnatRule.query.filter_by(import_group=group).all()
    if not rules:
        return None
    if any(rule.closed_by_group for rule in rules):
        raise CgnatRuleConflict("Esta importação já foi substituída por outra; apague a mais recente primeiro")
    rule_ids = [rule.id for rule in rules]
    AbuseIncident.query.filter(AbuseIncident.cgnat_rule_id.in_(rule_ids)).update(
        {"cgnat_rule_id": None, "private_ip": None}, synchronize_session=False
    )
    for reopened in CgnatRule.query.filter_by(closed_by_group=group).all():
        reopened.valid_to = None
        reopened.closed_by_group = None
    for rule in rules:
        db.session.delete(rule)
    db.session.flush()
    return recompute_private_ips()


def recompute_private_ips():
    """Recalcula o IP privado de todos os incidentes com porta e horário."""
    rules = CgnatRule.query.all()
    changed = 0
    query = AbuseIncident.query.filter(
        AbuseIncident.source_port.isnot(None), AbuseIncident.occurred_at.isnot(None)
    )
    for incident in query.yield_per(500):
        before = (incident.private_ip, incident.cgnat_rule_id)
        apply_cgnat(incident, rules)
        if (incident.private_ip, incident.cgnat_rule_id) != before:
            changed += 1
    return changed


# --- leitura do e-mail guardado ----------------------------------------------------

def read_raw_message(record):
    """Bytes do .eml guardado, ou None se expurgado/ausente."""
    if not record.raw_path or record.raw_purged_at is not None:
        return None
    base = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    path = (base / record.raw_path).resolve()
    if base not in path.parents or not path.is_file():
        return None
    return path.read_bytes()


def reprocess_message(record):
    """Lê de novo uma mensagem sem incidentes (ex.: prefixos configurados depois)."""
    if record.status not in ("unrecognized", "error"):
        raise ValueError("Só mensagens não reconhecidas ou com erro podem ser reprocessadas")
    raw = read_raw_message(record)
    if raw is None:
        raise ValueError("O e-mail original não está mais disponível")
    message = message_from_bytes(raw, policy=policy.compat32)
    try:
        result = parse_message(message, parser_settings_from(get_abuse_settings()))
    except Exception as exc:
        record.status = "error"
        record.error = f"{type(exc).__name__}: {exc}"[:2000]
        return 0
    record.parser = result.parser
    record.status = result.status
    record.error = "; ".join(result.notes) if result.notes else None
    rules = CgnatRule.query.all()
    for data in result.incidents:
        db.session.add(_incident_from(record, data, rules))
    return len(result.incidents)
