"""API do módulo de notificações de abuse.

IP + porta + horário e o vínculo com o assinante são dados pessoais: toda rota
exige usuário com ``abuse_access`` (a API key de serviço é recusada, porque não
identifica quem acessou) e as consultas e alterações vão para o log de auditoria.
"""

import csv
import io
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, policy
from functools import wraps
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Response, g, jsonify, request
from sqlalchemy import and_, or_

from ..abuse_parsers import INCIDENT_TYPES, message_attachments, message_text
from ..abuse_services import (
    apply_cgnat_plan,
    delete_cgnat_group,
    get_abuse_settings,
    get_session_resolver,
    parser_settings_from,
    plan_cgnat_import,
    plan_manual_rule,
    read_raw_message,
    reprocess_message,
)
from ..cgnat import ALLOCATIONS, CgnatRuleConflict, CgnatRuleError, blocks_per_ip, private_to_public
from ..cgnat_import import CgnatImportError
from ..models import (
    AbuseAuditLog,
    AbuseIncident,
    AbuseMailboxState,
    AbuseMessage,
    CgnatRule,
    User,
    db,
)
from . import api_bp
from .auth import current_actor_user, require_auth

INCIDENT_STATUSES = ("new", "review", "identified", "handled", "discarded")
MESSAGE_STATUSES = ("processed", "unrecognized", "error")
MAX_PER_PAGE = 100
EXPORT_LIMIT = 50_000
EDITABLE_FIELDS = ("pppoe_login", "hubsoft_customer_code", "action_taken", "notes")
FIELD_LIMITS = {"pppoe_login": 120, "hubsoft_customer_code": 60, "action_taken": 5000, "notes": 5000}


# --- acesso e auditoria -------------------------------------------------------------

def require_abuse_access(view):
    @wraps(view)
    @require_auth
    def wrapped(*args, **kwargs):
        user = current_actor_user()
        if user is None:
            return jsonify(error="O módulo de abuse exige login de usuário; a API key de serviço não é aceita."), 403
        if not user.abuse_access:
            return jsonify(error="Seu usuário não tem acesso ao módulo de abuse."), 403
        return view(*args, **kwargs)

    return wrapped


def client_address():
    forwarded = request.headers.get("X-Forwarded-For", "")
    first = forwarded.split(",")[0].strip()
    return (first or request.headers.get("X-Real-IP") or request.remote_addr or "")[:64] or None


def audit(action, incident=None, message=None, details=None, user=None):
    actor = user or current_actor_user()
    db.session.add(
        AbuseAuditLog(
            user_id=actor.id if actor else None,
            incident_id=incident.id if incident is not None else None,
            abuse_message_id=message.id if message is not None else None,
            action=action,
            details=json.dumps(details, ensure_ascii=False, default=str) if details else None,
            remote_addr=client_address(),
        )
    )


def iso_utc(value):
    return value.isoformat() + "Z" if value is not None else None


def error(message, status=400):
    return jsonify(error=message), status


# --- serialização --------------------------------------------------------------------

def public_kind(ip_text, rule):
    ip = ipaddress.ip_address(ip_text)
    if ip.version == 6:
        return "ipv6"
    if rule is not None:
        return "cgnat"
    in_any_pool = any(ip in ipaddress.ip_network(r.public_prefix) for r in CgnatRule.query.all())
    return "cgnat" if in_any_pool else "dedicated"


def recurrence(incident, days):
    if incident.status == "discarded":
        return [], []
    reference = incident.occurred_at or incident.created_at
    start, end = reference - timedelta(days=days), reference + timedelta(days=days)
    moment = db.func.coalesce(AbuseIncident.occurred_at, AbuseIncident.created_at)
    base = AbuseIncident.query.filter(AbuseIncident.id != incident.id, AbuseIncident.status != "discarded", moment >= start, moment <= end)

    customer = []
    if incident.pppoe_login:
        customer.append(AbuseIncident.pppoe_login == incident.pppoe_login)
    if incident.hubsoft_customer_code:
        customer.append(AbuseIncident.hubsoft_customer_code == incident.hubsoft_customer_code)
    strong = base.filter(or_(*customer)).order_by(moment.desc()).limit(50).all() if customer else []
    strong_ids = {item.id for item in strong}
    weak = []
    if incident.private_ip:
        weak = [
            item
            for item in base.filter(AbuseIncident.private_ip == incident.private_ip).order_by(moment.desc()).limit(50)
            if item.id not in strong_ids
        ]
    return strong, weak


def serialize_incident_row(incident, days=None):
    data = {
        "id": incident.id,
        "abuse_message_id": incident.abuse_message_id,
        "public_ip": incident.public_ip,
        "source_port": incident.source_port,
        "destination_ip": incident.destination_ip,
        "destination_port": incident.destination_port,
        "occurred_at": iso_utc(incident.occurred_at),
        "occurred_at_raw": incident.occurred_at_raw,
        "timezone_used": incident.timezone_used,
        "timezone_assumed": incident.timezone_assumed,
        "incident_type": incident.incident_type,
        "raw_type": incident.raw_type,
        "status": incident.status,
        "review_reasons": json.loads(incident.review_reasons) if incident.review_reasons else [],
        "private_ip": incident.private_ip,
        "cgnat_rule_id": incident.cgnat_rule_id,
        "pppoe_login": incident.pppoe_login,
        "hubsoft_customer_code": incident.hubsoft_customer_code,
        "anonymized_at": iso_utc(incident.anonymized_at),
        "created_at": iso_utc(incident.created_at),
        "updated_at": iso_utc(incident.updated_at),
    }
    if incident.status == "discarded":
        entry = AbuseAuditLog.query.filter_by(incident_id=incident.id, action="discard").order_by(AbuseAuditLog.id.desc()).first()
        data["discard"] = {
            "reason": json.loads(entry.details)["reason"],
            "at": iso_utc(entry.created_at), "by": serialize_user_ref(entry.user_id),
        } if entry else None
    if days is not None:
        strong, weak = recurrence(incident, days)
        data["recurrence"] = {"customer": len(strong), "private_ip": len(weak)}
    return data


def serialize_short(incident):
    return {
        "id": incident.id,
        "public_ip": incident.public_ip,
        "private_ip": incident.private_ip,
        "occurred_at": iso_utc(incident.occurred_at),
        "created_at": iso_utc(incident.created_at),
        "incident_type": incident.incident_type,
        "status": incident.status,
        "pppoe_login": incident.pppoe_login,
        "hubsoft_customer_code": incident.hubsoft_customer_code,
    }


def serialize_user_ref(user_id):
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    return {"id": user.id, "username": user.username} if user else {"id": user_id, "username": None}


def serialize_message(record, with_counts=True):
    data = {
        "id": record.id,
        "message_id": record.message_id,
        "sender": record.sender,
        "sender_domain": record.sender_domain,
        "subject": record.subject,
        "received_at": iso_utc(record.received_at),
        "created_at": iso_utc(record.created_at),
        "parser": record.parser,
        "status": record.status,
        "error": record.error,
        "raw_size": record.raw_size,
        "raw_available": bool(record.raw_path) and record.raw_purged_at is None,
        "raw_purged_at": iso_utc(record.raw_purged_at),
    }
    if with_counts:
        data["incident_count"] = AbuseIncident.query.filter_by(abuse_message_id=record.id).count()
    return data


def serialize_rule(rule):
    return {
        "id": rule.id,
        "private_prefix": rule.private_prefix,
        "public_prefix": rule.public_prefix,
        "ports_per_subscriber": rule.ports_per_subscriber,
        "first_port": rule.first_port,
        "allocation": rule.allocation,
        "blocks_per_ip": blocks_per_ip(rule),
        "valid_from": iso_utc(rule.valid_from),
        "valid_to": iso_utc(rule.valid_to),
        "pool_name": rule.pool_name,
        "import_group": rule.import_group,
        "closed_by_group": rule.closed_by_group,
        "source_filename": rule.source_filename,
        "source_md5": rule.source_md5,
        "notes": rule.notes,
        "created_by": serialize_user_ref(rule.created_by_user_id),
        "created_at": iso_utc(rule.created_at),
        "incident_count": AbuseIncident.query.filter_by(cgnat_rule_id=rule.id).count() if rule.id else 0,
    }


def serialize_settings(settings):
    parsed = parser_settings_from(settings)
    return {
        "own_prefixes": parsed.own_prefixes,
        "sender_timezones": parsed.sender_timezones,
        "lookup_window_minutes": settings.lookup_window_minutes,
        "recurrence_days": settings.recurrence_days,
        "raw_retention_days": settings.raw_retention_days,
        "incident_anonymize_days": settings.incident_anonymize_days,
        "last_retention_run_at": iso_utc(settings.last_retention_run_at),
        "updated_at": iso_utc(settings.updated_at),
    }


# --- filtros ---------------------------------------------------------------------------

def parse_utc(value, field):
    """Aceita ISO 8601; com fuso converte para UTC, sem fuso assume UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Data inválida em {field}.") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def incidents_query(args):
    query = AbuseIncident.query
    status = (args.get("status") or "").strip()
    if status:
        statuses = [item for item in status.split(",") if item in INCIDENT_STATUSES]
        if not statuses:
            raise ValueError("Status inválido.")
        query = query.filter(AbuseIncident.status.in_(statuses))
    else:
        query = query.filter(AbuseIncident.status != "discarded")
    incident_type = (args.get("type") or "").strip()
    if incident_type:
        if incident_type not in INCIDENT_TYPES:
            raise ValueError("Tipo inválido.")
        query = query.filter(AbuseIncident.incident_type == incident_type)
    moment = db.func.coalesce(AbuseIncident.occurred_at, AbuseIncident.created_at)
    date_from = parse_utc(args.get("from"), "from")
    date_to = parse_utc(args.get("to"), "to")
    if date_from:
        query = query.filter(moment >= date_from)
    if date_to:
        query = query.filter(moment < date_to)
    q = (args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                AbuseIncident.public_ip == q,
                AbuseIncident.private_ip == q,
                AbuseIncident.pppoe_login.ilike(like),
                AbuseIncident.hubsoft_customer_code == q,
            )
        )
    message_id = args.get("message", type=int)
    if message_id:
        query = query.filter(AbuseIncident.abuse_message_id == message_id)
    return query.order_by(moment.desc(), AbuseIncident.id.desc())


def filters_for_audit(args):
    return {key: args.get(key) for key in ("status", "type", "from", "to", "q", "message", "page") if args.get(key)}


# --- status ----------------------------------------------------------------------------

@api_bp.route("/abuse/status", methods=["GET"])
@require_abuse_access
def abuse_status():
    counts = dict(
        db.session.query(AbuseIncident.status, db.func.count(AbuseIncident.id)).group_by(AbuseIncident.status).all()
    )
    message_counts = dict(
        db.session.query(AbuseMessage.status, db.func.count(AbuseMessage.id)).group_by(AbuseMessage.status).all()
    )
    mailboxes = [
        {
            "mailbox": state.mailbox,
            "last_uid": state.last_uid,
            "uidvalidity": state.uidvalidity,
            "last_run_at": iso_utc(state.last_run_at),
            "last_error": state.last_error,
        }
        for state in AbuseMailboxState.query.order_by(AbuseMailboxState.mailbox).all()
    ]
    settings = get_abuse_settings()
    return jsonify(
        incidents={status: counts.get(status, 0) for status in INCIDENT_STATUSES},
        messages={status: message_counts.get(status, 0) for status in MESSAGE_STATUSES},
        mailboxes=mailboxes,
        own_prefixes_configured=bool(parser_settings_from(settings).networks),
        cgnat_rules=CgnatRule.query.count(),
        last_retention_run_at=iso_utc(settings.last_retention_run_at),
    )


# --- log de auditoria ------------------------------------------------------------------

AUDIT_ACTIONS = (
    "list",
    "view",
    "update",
    "export_csv",
    "list_messages",
    "view_raw",
    "download_raw",
    "reprocess",
    "rule_change",
    "settings_change",
    "access_grant",
    "access_revoke",
    "anonymize",
    "purge_raw",
    "list_audit",
)


@api_bp.route("/abuse/audit", methods=["GET"])
@require_abuse_access
def list_abuse_audit():
    query = AbuseAuditLog.query
    action = (request.args.get("action") or "").strip()
    if action:
        if action not in AUDIT_ACTIONS:
            return error("Ação inválida.")
        query = query.filter(AbuseAuditLog.action == action)
    username = (request.args.get("user") or "").strip()
    if username == "sistema":
        query = query.filter(AbuseAuditLog.user_id.is_(None))
    elif username:
        user = User.query.filter_by(username=username).first()
        query = query.filter(AbuseAuditLog.user_id == (user.id if user else -1))
    incident_id = request.args.get("incident", type=int)
    if incident_id:
        query = query.filter(AbuseAuditLog.incident_id == incident_id)
    message_id = request.args.get("message", type=int)
    if message_id:
        query = query.filter(AbuseAuditLog.abuse_message_id == message_id)
    try:
        date_from = parse_utc(request.args.get("from"), "from")
        date_to = parse_utc(request.args.get("to"), "to")
    except ValueError as exc:
        return error(str(exc))
    if date_from:
        query = query.filter(AbuseAuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AbuseAuditLog.created_at < date_to)
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 50, type=int), 1), MAX_PER_PAGE)
    pagination = query.order_by(AbuseAuditLog.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    users = {}

    def username_of(user_id):
        if user_id is None:
            return None
        if user_id not in users:
            ref = db.session.get(User, user_id)
            users[user_id] = ref.username if ref else f"#{user_id}"
        return users[user_id]

    items = [
        {
            "id": entry.id,
            "created_at": iso_utc(entry.created_at),
            "user": username_of(entry.user_id),
            "action": entry.action,
            "incident_id": entry.incident_id,
            "abuse_message_id": entry.abuse_message_id,
            "details": json.loads(entry.details) if entry.details else None,
            "remote_addr": entry.remote_addr,
        }
        for entry in pagination.items
    ]
    audit("list_audit", details={key: request.args.get(key) for key in request.args if key != "per_page"})
    db.session.commit()
    return jsonify(items=items, page=pagination.page, per_page=per_page, total=pagination.total, pages=pagination.pages)


# --- incidentes ------------------------------------------------------------------------

@api_bp.route("/abuse/incidents", methods=["GET"])
@require_abuse_access
def list_abuse_incidents():
    try:
        query = incidents_query(request.args)
    except ValueError as exc:
        return error(str(exc))
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 20, type=int), 1), MAX_PER_PAGE)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    days = get_abuse_settings().recurrence_days
    audit("list", details={"filters": filters_for_audit(request.args), "count": len(pagination.items)})
    db.session.commit()
    return jsonify(
        items=[serialize_incident_row(item, days) for item in pagination.items],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


@api_bp.route("/abuse/incidents/export.csv", methods=["GET"])
@require_abuse_access
def export_abuse_incidents():
    try:
        query = incidents_query(request.args)
    except ValueError as exc:
        return error(str(exc))
    items = query.limit(EXPORT_LIMIT + 1).all()
    if len(items) > EXPORT_LIMIT:
        return error(f"Mais de {EXPORT_LIMIT} incidentes; refine os filtros antes de exportar.")

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(
        [
            "id",
            "status",
            "tipo",
            "tipo_original",
            "ocorrido_em_utc",
            "horario_original",
            "fuso",
            "fuso_assumido",
            "ip_publico",
            "porta_origem",
            "ip_destino",
            "porta_destino",
            "ip_privado",
            "login_pppoe",
            "codigo_cliente",
            "acao",
            "remetente",
            "recebido_em_utc",
        ]
    )
    senders = {}
    for item in items:
        if item.abuse_message_id not in senders:
            record = db.session.get(AbuseMessage, item.abuse_message_id)
            senders[item.abuse_message_id] = (record.sender, record.received_at) if record else (None, None)
        sender, received = senders[item.abuse_message_id]
        writer.writerow(
            [
                item.id,
                item.status,
                item.incident_type,
                item.raw_type or "",
                item.occurred_at.isoformat() if item.occurred_at else "",
                item.occurred_at_raw or "",
                item.timezone_used or "",
                "sim" if item.timezone_assumed else "não",
                item.public_ip,
                item.source_port or "",
                item.destination_ip or "",
                item.destination_port or "",
                item.private_ip or "",
                item.pppoe_login or "",
                item.hubsoft_customer_code or "",
                (item.action_taken or "").replace("\r", " ").replace("\n", " "),
                sender or "",
                received.isoformat() if received else "",
            ]
        )
    audit("export_csv", details={"filters": filters_for_audit(request.args), "count": len(items)})
    db.session.commit()
    filename = f"incidentes-abuse-{datetime.utcnow():%Y%m%d-%H%M%S}.csv"
    return Response(
        "﻿" + buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@api_bp.route("/abuse/incidents/<int:incident_id>", methods=["GET"])
@require_abuse_access
def get_abuse_incident(incident_id):
    incident = db.session.get(AbuseIncident, incident_id)
    if incident is None:
        return error("Incidente não encontrado.", 404)
    data = incident_detail(incident)
    audit("view", incident=incident, message=db.session.get(AbuseMessage, incident.abuse_message_id))
    db.session.commit()
    return jsonify(data)


def incident_detail(incident):
    settings = get_abuse_settings()
    record = db.session.get(AbuseMessage, incident.abuse_message_id)
    rule = db.session.get(CgnatRule, incident.cgnat_rule_id) if incident.cgnat_rule_id else None

    data = serialize_incident_row(incident)
    data.update(
        action_taken=incident.action_taken,
        notes=incident.notes,
        identified_by=serialize_user_ref(incident.identified_by_user_id),
        identified_at=iso_utc(incident.identified_at),
        handled_by=serialize_user_ref(incident.handled_by_user_id),
        handled_at=iso_utc(incident.handled_at),
        public_kind=public_kind(incident.public_ip, rule),
        cgnat_rule=serialize_rule(rule) if rule else None,
        port_block=None,
        lookup_window=None,
        sessions=[],
        session_resolver=None,
    )
    if rule is not None and incident.private_ip:
        mapping = private_to_public(incident.private_ip, incident.occurred_at, [rule])
        if mapping is not None:
            data["port_block"] = {"start": mapping.port_start, "end": mapping.port_end, "block": mapping.block}
    if incident.occurred_at is not None:
        minutes = settings.lookup_window_minutes
        start = incident.occurred_at - timedelta(minutes=minutes)
        end = incident.occurred_at + timedelta(minutes=minutes)
        data["lookup_window"] = {"minutes": minutes, "start": iso_utc(start), "end": iso_utc(end)}
        if incident.private_ip:
            resolver = get_session_resolver()
            data["session_resolver"] = resolver.name
            data["sessions"] = [
                {
                    "login": match.login,
                    "session_start": iso_utc(match.session_start),
                    "session_end": iso_utc(match.session_end),
                    "source": match.source,
                }
                for match in resolver.resolve(incident.private_ip, start, end)
            ]
    strong, weak = recurrence(incident, settings.recurrence_days)
    data["recurrence"] = {
        "days": settings.recurrence_days,
        "customer": [serialize_short(item) for item in strong],
        "private_ip": [serialize_short(item) for item in weak],
    }
    data["message"] = serialize_message(record) if record else None
    data["siblings"] = [
        serialize_short(item)
        for item in AbuseIncident.query.filter(
            AbuseIncident.abuse_message_id == incident.abuse_message_id, AbuseIncident.id != incident.id
        )
        .order_by(AbuseIncident.id)
        .limit(200)
    ]
    return data


@api_bp.route("/abuse/incidents/<int:incident_id>", methods=["PATCH"])
@require_abuse_access
def update_abuse_incident(incident_id):
    incident = db.session.get(AbuseIncident, incident_id)
    if incident is None:
        return error("Incidente não encontrado.", 404)
    if incident.status == "discarded":
        return error("Incidente descartado; não pode mais ser alterado.", 409)
    if incident.anonymized_at is not None:
        return error("Incidente anonimizado pela retenção; não pode mais ser alterado.", 409)
    payload = request.get_json(silent=True) or {}
    user = current_actor_user()

    before = {field: getattr(incident, field) for field in EDITABLE_FIELDS + ("status",)}
    for field in EDITABLE_FIELDS:
        if field in payload:
            value = payload[field]
            if value is not None and not isinstance(value, str):
                return error(f"Valor inválido em {field}.")
            value = (value or "").strip() or None
            if value and len(value) > FIELD_LIMITS[field]:
                return error(f"{field} excede {FIELD_LIMITS[field]} caracteres.")
            setattr(incident, field, value)

    status = payload.get("status", incident.status)
    if status == "discarded":
        return error("Use a ação de descarte e informe o motivo.")
    if status not in INCIDENT_STATUSES:
        return error("Status inválido.")
    if status == "identified" and not (incident.pppoe_login or incident.hubsoft_customer_code):
        return error("Para marcar como identificado, informe o login PPPoE ou o código do cliente.")
    if status == "handled" and not incident.action_taken:
        return error("Para marcar como tratado, descreva a ação tomada.")

    now = datetime.utcnow()
    if status != before["status"]:
        if status == "identified":
            incident.identified_by_user_id, incident.identified_at = user.id, now
        if status == "handled":
            incident.handled_by_user_id, incident.handled_at = user.id, now
            if (incident.pppoe_login or incident.hubsoft_customer_code) and not incident.identified_at:
                incident.identified_by_user_id, incident.identified_at = user.id, now
        elif before["status"] == "handled":
            # Reaberto: o prazo de anonimização só volta a contar quando tratar de novo.
            incident.handled_by_user_id, incident.handled_at = None, None
    incident.status = status

    after = {field: getattr(incident, field) for field in EDITABLE_FIELDS + ("status",)}
    changes = {field: {"before": before[field], "after": after[field]} for field in after if before[field] != after[field]}
    if changes:
        audit("update", incident=incident, details={"changes": changes})
    db.session.commit()
    return jsonify(incident_detail(incident))


# --- mensagens -------------------------------------------------------------------------

@api_bp.route("/abuse/messages", methods=["GET"])
@require_abuse_access
def list_abuse_messages():
    query = AbuseMessage.query
    status = (request.args.get("status") or "").strip()
    if status:
        statuses = [item for item in status.split(",") if item in MESSAGE_STATUSES]
        if not statuses:
            return error("Status inválido.")
        query = query.filter(AbuseMessage.status.in_(statuses))
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(or_(AbuseMessage.sender.ilike(like), AbuseMessage.subject.ilike(like)))
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 20, type=int), 1), MAX_PER_PAGE)
    moment = db.func.coalesce(AbuseMessage.received_at, AbuseMessage.created_at)
    pagination = query.order_by(moment.desc(), AbuseMessage.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    audit("list_messages", details={"status": status or None, "q": q or None, "page": page})
    db.session.commit()
    return jsonify(
        items=[serialize_message(item) for item in pagination.items],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


@api_bp.route("/abuse/messages/<int:message_id>", methods=["GET"])
@require_abuse_access
def get_abuse_message(message_id):
    record = db.session.get(AbuseMessage, message_id)
    if record is None:
        return error("Mensagem não encontrada.", 404)
    data = serialize_message(record)
    raw = read_raw_message(record)
    data["body_text"] = None
    data["attachments"] = []
    data["headers"] = []
    if raw is not None:
        parsed = message_from_bytes(raw, policy=policy.compat32)
        data["body_text"] = message_text(parsed)
        data["attachments"] = message_attachments(parsed)
        data["headers"] = [
            {"name": name, "value": str(value)[:2000]}
            for name, value in parsed.items()
            if name.lower() in ("from", "to", "cc", "reply-to", "subject", "date", "message-id", "x-arf")
        ]
    data["incidents"] = [
        serialize_short(item)
        for item in AbuseIncident.query.filter_by(abuse_message_id=record.id).order_by(AbuseIncident.id).limit(500)
    ]
    audit("view_raw", message=record)
    db.session.commit()
    return jsonify(data)


@api_bp.route("/abuse/messages/<int:message_id>/raw", methods=["GET"])
@require_abuse_access
def download_abuse_message(message_id):
    record = db.session.get(AbuseMessage, message_id)
    if record is None:
        return error("Mensagem não encontrada.", 404)
    raw = read_raw_message(record)
    if raw is None:
        return error("O e-mail original não está mais disponível (expurgado pela retenção).", 410)
    audit("download_raw", message=record)
    db.session.commit()
    return Response(
        raw,
        mimetype="message/rfc822",
        headers={"Content-Disposition": f'attachment; filename="abuse-{record.id}.eml"'},
    )


BULK_REPROCESS_LIMIT = 500


@api_bp.route("/abuse/messages/reprocess", methods=["POST"])
@require_abuse_access
def reprocess_abuse_messages():
    """Reprocessa em lote as mensagens não reconhecidas/com erro (ex.: após cadastrar prefixos)."""
    payload = request.get_json(silent=True) or {}
    statuses = payload.get("statuses") or ["unrecognized"]
    if not isinstance(statuses, list) or not statuses or any(item not in ("unrecognized", "error") for item in statuses):
        return error("statuses deve conter unrecognized e/ou error.")
    try:
        after_id = int(payload.get("after_id") or 0)
    except (TypeError, ValueError):
        return error("after_id inválido.")
    base = AbuseMessage.query.filter(
        AbuseMessage.status.in_(statuses),
        AbuseMessage.raw_path.isnot(None),
        AbuseMessage.raw_purged_at.is_(None),
    )
    # Cursor por id: as que continuarem não reconhecidas não voltam no próximo lote.
    batch = base.filter(AbuseMessage.id > after_id).order_by(AbuseMessage.id).limit(BULK_REPROCESS_LIMIT).all()
    recognized = incidents = 0
    skipped = []
    for record in batch:
        try:
            created = reprocess_message(record)
        except ValueError as exc:
            skipped.append({"id": record.id, "error": str(exc)})
            # Sem o .eml não há o que reler; marca para não voltar ao lote.
            record.status = "error"
            record.error = str(exc)[:2000]
            continue
        incidents += created
        if record.status == "processed":
            recognized += 1
    db.session.flush()
    last_id = batch[-1].id if batch else after_id
    remaining = base.filter(AbuseMessage.id > last_id).count()
    audit(
        "reprocess",
        details={
            "bulk": True,
            "statuses": statuses,
            "messages": len(batch),
            "recognized": recognized,
            "incidents": incidents,
            "skipped": skipped[:20],
        },
    )
    db.session.commit()
    return jsonify(
        processed=len(batch),
        recognized=recognized,
        incidents=incidents,
        skipped=len(skipped),
        remaining=remaining,
        last_id=last_id,
    )


@api_bp.route("/abuse/messages/<int:message_id>/reprocess", methods=["POST"])
@require_abuse_access
def reprocess_abuse_message(message_id):
    record = db.session.get(AbuseMessage, message_id)
    if record is None:
        return error("Mensagem não encontrada.", 404)
    try:
        created = reprocess_message(record)
    except ValueError as exc:
        return error(str(exc))
    audit("reprocess", message=record, details={"incidents": created, "status": record.status})
    db.session.commit()
    return jsonify(serialize_message(record))


@api_bp.route("/abuse/incidents/discard", methods=["POST"])
@require_abuse_access
def discard_abuse_incidents():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error("Informe ids e motivo do descarte.")
    ids, reason = payload.get("ids"), payload.get("reason")
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 100
            or any(type(item) is not int or item <= 0 for item in ids)):
        return error("Selecione de 1 a 100 incidentes por chamada.")
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 2000:
        return error("Informe um motivo de até 2000 caracteres.")
    records = AbuseIncident.query.filter(AbuseIncident.id.in_(set(ids))).with_for_update().all()
    if len(records) != len(set(ids)):
        return error("Incidente não encontrado.", 404)
    changed = 0
    for incident in records:
        if incident.status == "discarded":
            continue
        before = incident.status
        incident.status = "discarded"
        incident.handled_at = datetime.utcnow()
        incident.handled_by_user_id = current_actor_user().id
        audit("discard", incident=incident, details={"reason": reason.strip(), "previous_status": before})
        changed += 1
    db.session.commit()
    return jsonify(discarded=changed)


@api_bp.route("/abuse/incidents/restore", methods=["POST"])
@require_abuse_access
def restore_abuse_incidents():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error("Informe ids e motivo da restauração.")
    ids, reason = payload.get("ids"), payload.get("reason")
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 100
            or any(type(item) is not int or item <= 0 for item in ids)):
        return error("Selecione de 1 a 100 incidentes por chamada.")
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 2000:
        return error("Informe um motivo de até 2000 caracteres.")
    records = AbuseIncident.query.filter(AbuseIncident.id.in_(set(ids))).with_for_update().all()
    if len(records) != len(set(ids)):
        return error("Incidente não encontrado.", 404)
    if any(item.status == "discarded" and item.anonymized_at is not None for item in records):
        return error("Incidentes anonimizados pela retenção não podem ser restaurados.", 409)
    changed = 0
    for incident in records:
        if incident.status != "discarded":
            continue
        incident.status = "review"
        incident.handled_at = None
        incident.handled_by_user_id = None
        audit("restore", incident=incident, details={
            "reason": reason.strip(), "previous_status": "discarded", "status": "review",
        })
        changed += 1
    db.session.commit()
    return jsonify(restored=changed)


# --- regras de CGNAT -------------------------------------------------------------------

@api_bp.route("/abuse/cgnat-rules", methods=["GET"])
@require_abuse_access
def list_cgnat_rules():
    rules = CgnatRule.query.order_by(CgnatRule.valid_from.desc(), CgnatRule.public_prefix).all()
    return jsonify(items=[serialize_rule(rule) for rule in rules])


def serialize_plan(plan, changed=None):
    return {
        "import_group": plan.group,
        "rules": [serialize_rule(rule) for rule in plan.rules],
        "closings": [
            {"rule": serialize_rule(rule), "new_valid_to": iso_utc(valid_to)} for rule, valid_to in plan.closings
        ],
        "pools": [
            {
                "pool_name": pool.pool_name,
                "method": pool.method,
                "exported_at": pool.exported_at,
                "entry_count": pool.entry_count,
                "warnings": pool.warnings,
            }
            for pool in plan.pools
        ],
        "incidents_recalculated": changed,
    }


def validity_from_form(source):
    valid_from = parse_utc(source.get("valid_from"), "valid_from")
    if valid_from is None:
        raise ValueError("Informe o início da vigência.")
    valid_to = parse_utc(source.get("valid_to"), "valid_to")
    return valid_from, valid_to


@api_bp.route("/abuse/cgnat-rules/import", methods=["POST"])
@require_abuse_access
def import_cgnat_rules():
    try:
        valid_from, valid_to = validity_from_form(request.form)
    except ValueError as exc:
        return error(str(exc))
    uploads = request.files.getlist("files")
    files = [(upload.filename, upload.read()) for upload in uploads if upload and upload.filename]
    notes = (request.form.get("notes") or "").strip()[:2000] or None
    dry_run = (request.form.get("dry_run") or "").lower() in ("1", "true", "yes", "sim")
    user = current_actor_user()
    try:
        plan = plan_cgnat_import(files, valid_from, valid_to, notes=notes, user_id=user.id)
    except (CgnatImportError, CgnatRuleError, CgnatRuleConflict) as exc:
        db.session.rollback()
        return error(str(exc), 409 if isinstance(exc, CgnatRuleConflict) else 400)
    if dry_run:
        payload = serialize_plan(plan)
        db.session.rollback()
        return jsonify(dry_run=True, **payload)
    changed = apply_cgnat_plan(plan)
    audit(
        "rule_change",
        details={
            "operation": "import",
            "import_group": plan.group,
            "files": [name for name, _ in files],
            "rules": [f"{r.public_prefix} <- {r.private_prefix}" for r in plan.rules],
            "valid_from": valid_from,
            "valid_to": valid_to,
            "closed": [{"rule_id": r.id, "valid_to": v} for r, v in plan.closings],
            "incidents_recalculated": changed,
        },
    )
    db.session.commit()
    return jsonify(dry_run=False, **serialize_plan(plan, changed)), 201


@api_bp.route("/abuse/cgnat-rules", methods=["POST"])
@require_abuse_access
def create_cgnat_rule():
    payload = request.get_json(silent=True) or {}
    try:
        valid_from, valid_to = validity_from_form(payload)
        values = {
            "private_prefix": str(ipaddress.IPv4Network(str(payload.get("private_prefix", "")).strip())),
            "public_prefix": str(ipaddress.IPv4Network(str(payload.get("public_prefix", "")).strip())),
            "ports_per_subscriber": int(payload.get("ports_per_subscriber")),
            "first_port": int(payload.get("first_port")),
            "allocation": str(payload.get("allocation", "")),
            "valid_from": valid_from,
            "valid_to": valid_to,
            "pool_name": (str(payload.get("pool_name") or "").strip()[:120] or None),
            "notes": (str(payload.get("notes") or "").strip()[:2000] or None),
        }
    except (TypeError, ValueError) as exc:
        return error(f"Dados inválidos: {exc}")
    if values["allocation"] not in ALLOCATIONS:
        return error("Alocação deve ser interleaved ou sequential.")
    user = current_actor_user()
    try:
        plan = plan_manual_rule(values, user_id=user.id)
    except (CgnatRuleError, CgnatRuleConflict) as exc:
        db.session.rollback()
        return error(str(exc), 409 if isinstance(exc, CgnatRuleConflict) else 400)
    if payload.get("dry_run"):
        result = serialize_plan(plan)
        db.session.rollback()
        return jsonify(dry_run=True, **result)
    changed = apply_cgnat_plan(plan)
    audit(
        "rule_change",
        details={"operation": "create", "import_group": plan.group, "rule": values, "incidents_recalculated": changed},
    )
    db.session.commit()
    return jsonify(dry_run=False, **serialize_plan(plan, changed)), 201


@api_bp.route("/abuse/cgnat-rules/groups/<group>", methods=["DELETE"])
@require_abuse_access
def delete_cgnat_rule_group(group):
    rules = CgnatRule.query.filter_by(import_group=group).all()
    summary = [f"{r.public_prefix} <- {r.private_prefix}" for r in rules]
    try:
        changed = delete_cgnat_group(group)
    except CgnatRuleConflict as exc:
        db.session.rollback()
        return error(str(exc), 409)
    if changed is None:
        return error("Importação não encontrada.", 404)
    audit(
        "rule_change",
        details={"operation": "delete", "import_group": group, "rules": summary, "incidents_recalculated": changed},
    )
    db.session.commit()
    return jsonify(status="deleted", incidents_recalculated=changed)


# --- configurações -----------------------------------------------------------------------

@api_bp.route("/abuse/settings", methods=["GET"])
@require_abuse_access
def get_abuse_settings_route():
    return jsonify(serialize_settings(get_abuse_settings()))


def clean_prefixes(values):
    if not isinstance(values, list):
        raise ValueError("own_prefixes deve ser uma lista.")
    cleaned = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"Prefixo inválido: {text}") from exc
        if str(network) not in cleaned:
            cleaned.append(str(network))
    return cleaned


def clean_timezones(values):
    if not isinstance(values, dict):
        raise ValueError("sender_timezones deve ser um mapa domínio -> fuso.")
    cleaned = {}
    for domain, zone in values.items():
        domain = str(domain).strip().lower().lstrip(".")
        zone = str(zone).strip()
        if not domain:
            continue
        try:
            ZoneInfo(zone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Fuso inválido para {domain}: {zone}") from exc
        cleaned[domain] = zone
    return cleaned


def bounded_int(value, field, minimum, maximum, allow_none=False):
    if value in (None, "") and allow_none:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} deve ser um número inteiro.") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} deve estar entre {minimum} e {maximum}.")
    return number


@api_bp.route("/abuse/settings", methods=["PUT"])
@require_abuse_access
def update_abuse_settings_route():
    payload = request.get_json(silent=True) or {}
    settings = get_abuse_settings()
    before = serialize_settings(settings)
    try:
        if "own_prefixes" in payload:
            settings.own_prefixes = json.dumps(clean_prefixes(payload["own_prefixes"]))
        if "sender_timezones" in payload:
            settings.sender_timezones = json.dumps(clean_timezones(payload["sender_timezones"]))
        if "lookup_window_minutes" in payload:
            settings.lookup_window_minutes = bounded_int(payload["lookup_window_minutes"], "Janela", 1, 1440)
        if "recurrence_days" in payload:
            settings.recurrence_days = bounded_int(payload["recurrence_days"], "Reincidência", 1, 3650)
        if "raw_retention_days" in payload:
            settings.raw_retention_days = bounded_int(
                payload["raw_retention_days"], "Retenção", 1, 36500, allow_none=True
            )
        if "incident_anonymize_days" in payload:
            settings.incident_anonymize_days = bounded_int(
                payload["incident_anonymize_days"], "Anonimização", 1, 36500, allow_none=True
            )
    except ValueError as exc:
        db.session.rollback()
        return error(str(exc))
    after = serialize_settings(settings)
    changes = {
        key: {"before": before[key], "after": after[key]}
        for key in after
        if key not in ("updated_at", "last_retention_run_at") and before[key] != after[key]
    }
    if changes:
        audit("settings_change", details={"changes": changes})
    db.session.commit()
    return jsonify(serialize_settings(settings))


# --- acesso de usuários ao módulo --------------------------------------------------------

@api_bp.route("/abuse/users/<int:user_id>/access", methods=["POST"])
@require_abuse_access
def set_abuse_access(user_id):
    target = db.session.get(User, user_id)
    if target is None:
        return error("Usuário não encontrado.", 404)
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload.get("abuse_access"), bool):
        return error("Informe abuse_access (true/false).")
    granted = payload["abuse_access"]
    holders = User.query.filter(and_(User.abuse_access.is_(True), User.active.is_(True))).count()
    if target.abuse_access and not granted and holders <= 1:
        return error("Não é possível remover o último usuário com acesso ao módulo de abuse.")
    if target.abuse_access != granted:
        target.abuse_access = granted
        audit("access_grant" if granted else "access_revoke", details={"user_id": target.id, "username": target.username})
    db.session.commit()
    return jsonify(id=target.id, username=target.username, abuse_access=target.abuse_access)
