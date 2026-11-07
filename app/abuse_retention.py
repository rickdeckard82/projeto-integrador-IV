"""Retenção do módulo de abuse (LGPD).

- Incidente: anonimizado ``incident_anonymize_days`` depois de marcado como
  Tratado. Novo, Revisar e Identificado nunca são anonimizados. Saem login
  PPPoE, código do cliente, IP privado e porta de origem, e o IP público é
  truncado (IPv4 /24, IPv6 /48). Tipo, datas, ação e notas ficam para
  estatística.
- E-mail bruto (.eml): apagado ``raw_retention_days`` depois que todos os
  incidentes da mensagem foram tratados; mensagem sem incidente (não
  reconhecida ou com erro) conta a partir do recebimento. Os metadados da
  mensagem ficam.

Cada anonimização e cada expurgo vão para o log de auditoria (sem usuário:
ação do sistema).
"""

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from flask import current_app
from sqlalchemy import and_, exists, or_

from .abuse_services import get_abuse_settings
from .models import AbuseAuditLog, AbuseIncident, AbuseMessage, db

ANONYMIZED_FIELDS = ("pppoe_login", "hubsoft_customer_code", "private_ip", "source_port")


@dataclass
class RetentionStats:
    anonymized: int = 0
    purged: int = 0
    missing_files: int = 0
    errors: list = field(default_factory=list)


def truncate_ip(ip_text):
    ip = ipaddress.ip_address(ip_text)
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False).network_address)


def anonymize_incident(incident, now):
    removed = [name for name in ANONYMIZED_FIELDS if getattr(incident, name) is not None]
    incident.pppoe_login = None
    incident.hubsoft_customer_code = None
    incident.private_ip = None
    incident.source_port = None
    try:
        incident.public_ip = truncate_ip(incident.public_ip)
    except ValueError:
        incident.public_ip = "anonimizado"
    incident.anonymized_at = now
    return removed


def _audit(action, incident=None, message=None, details=None):
    db.session.add(
        AbuseAuditLog(
            user_id=None,
            incident_id=incident.id if incident is not None else None,
            abuse_message_id=message.id if message is not None else None,
            action=action,
            details=json.dumps(details, ensure_ascii=False, default=str) if details else None,
        )
    )


def anonymize_handled(now, days):
    cutoff = now - timedelta(days=days)
    query = AbuseIncident.query.filter(
        AbuseIncident.status.in_(("handled", "discarded")),
        AbuseIncident.anonymized_at.is_(None),
        AbuseIncident.handled_at.isnot(None),
        AbuseIncident.handled_at <= cutoff,
    )
    count = 0
    for incident in query.all():
        removed = anonymize_incident(incident, now)
        _audit("anonymize", incident=incident, details={"removed": removed, "handled_at": incident.handled_at})
        count += 1
    return count


def purgeable_messages(now, days):
    cutoff = now - timedelta(days=days)
    has_incident = exists().where(AbuseIncident.abuse_message_id == AbuseMessage.id)
    has_open = exists().where(
        and_(
            AbuseIncident.abuse_message_id == AbuseMessage.id,
            or_(~AbuseIncident.status.in_(("handled", "discarded")), AbuseIncident.handled_at.is_(None), AbuseIncident.handled_at > cutoff),
        )
    )
    received = db.func.coalesce(AbuseMessage.received_at, AbuseMessage.created_at)
    return AbuseMessage.query.filter(
        AbuseMessage.raw_purged_at.is_(None),
        AbuseMessage.raw_path.isnot(None),
        or_(
            and_(has_incident, ~has_open),
            and_(~has_incident, received <= cutoff, AbuseMessage.created_at <= cutoff),
        ),
    )


def purge_raw(now, days, stats):
    base = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    for message in purgeable_messages(now, days).all():
        path = (base / message.raw_path).resolve()
        if base not in path.parents:
            stats.errors.append(f"mensagem {message.id}: caminho fora da pasta de uploads")
            continue
        shared = AbuseMessage.query.filter(
            AbuseMessage.id != message.id,
            AbuseMessage.raw_path == message.raw_path,
            AbuseMessage.raw_purged_at.is_(None),
        ).first()
        existed = path.is_file()
        if existed and shared is None:
            try:
                path.unlink()
            except OSError as exc:
                stats.errors.append(f"mensagem {message.id}: {exc}")
                continue
        if not existed:
            stats.missing_files += 1
        message.raw_purged_at = now
        _audit("purge_raw", message=message, details={"raw_sha256": message.raw_sha256, "file_existed": existed})
        stats.purged += 1


def run_retention(now=None):
    now = now or datetime.utcnow()
    settings = get_abuse_settings()
    stats = RetentionStats()
    if settings.incident_anonymize_days:
        stats.anonymized = anonymize_handled(now, settings.incident_anonymize_days)
        db.session.flush()
    if settings.raw_retention_days:
        purge_raw(now, settings.raw_retention_days, stats)
    settings.last_retention_run_at = now
    db.session.commit()
    return stats
