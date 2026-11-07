"""Envio de comunicados por e-mail, histórico de envios e marcação de notificação no ofício."""

from datetime import datetime
from pathlib import Path

from flask import jsonify, request

from ..mailer import (
    MAX_ATTACHMENTS,
    MAX_ATTACHMENTS_BYTES,
    MAX_RECIPIENTS,
    describe_error,
    parse_recipients,
    send_email,
    smtp_config_problem,
    with_signature,
)
from ..models import ParameterSettings, SentEmail, User, db
from . import api_bp
from .auth import current_actor_user, require_auth
from ..rpz import build_rpz_zone
from ..services import (
    active_domain_names_for_office,
    configured_rpz_nameserver,
    office_ip_route_config,
    safe_filename,
)
from .routes import MAX_PER_PAGE, find_office, iso_utc, serialize_office


def serialize_sent_email(email, users_by_id):
    user = users_by_id.get(email.user_id)
    return {
        "id": email.id,
        "office_id": email.office_id,
        "office_number": email.office_number,
        "recipients": [item for item in email.recipients.split(",") if item],
        "subject": email.subject,
        "body": email.body,
        "attachments": [name for name in (email.attachments or "").split("\n") if name],
        "status": email.status,
        "error": email.error,
        "username": user.username if user else None,
        "created_at": iso_utc(email.created_at),
    }


def flag(payload, name):
    return str(payload.get(name) or "").strip().lower() in ("1", "true", "yes", "sim", "on")


def collect_attachments(office, payload, uploads):
    """[(nome, bytes)]: arquivos gerados do ofício (db.rpz.zone e config de IPs) e os
    enviados do computador. Levanta ValueError quando o pedido não pode ser atendido."""
    attachments = []
    if flag(payload, "attach_zone") or flag(payload, "attach_ips"):
        if office is None:
            raise ValueError("Selecione o ofício para anexar o db.rpz.zone ou a config de IPs.")
        name = safe_filename(office.office_number)
        if flag(payload, "attach_zone"):
            domains = active_domain_names_for_office(office.id)
            if not domains:
                raise ValueError("O ofício não tem domínios ativos para o db.rpz.zone.")
            zone = build_rpz_zone(domains, configured_rpz_nameserver())
            attachments.append((f"oficio-{name}-db.rpz.zone", zone.encode()))
        if flag(payload, "attach_ips"):
            config = office_ip_route_config(office)
            if not config:
                raise ValueError("O ofício não tem IPs ativos para a config de IPs.")
            attachments.append((f"oficio-{name}-config.txt", config.encode()))

    for upload in uploads:
        filename = Path(upload.filename or "").name.strip()
        if not filename:
            continue
        attachments.append((filename, upload.read()))

    if len(attachments) > MAX_ATTACHMENTS:
        raise ValueError(f"No máximo {MAX_ATTACHMENTS} anexos por e-mail.")
    if sum(len(data) for _, data in attachments) > MAX_ATTACHMENTS_BYTES:
        raise ValueError(f"Os anexos somam mais de {MAX_ATTACHMENTS_BYTES // (1024 * 1024)} MB.")
    return attachments


@api_bp.route("/communications/send", methods=["POST"])
@require_auth
def send_communication():
    # Com anexos do computador o front envia multipart/form-data; sem eles, JSON.
    multipart = request.mimetype == "multipart/form-data"
    payload = request.form if multipart else (request.get_json(silent=True) or {})
    subject = " ".join(str(payload.get("subject") or "").split())
    body = str(payload.get("body") or "").strip()
    recipients, invalid = parse_recipients(
        payload.getlist("recipients") if multipart else payload.get("recipients")
    )

    if invalid:
        return jsonify(error=f"Destinatário(s) inválido(s): {', '.join(invalid)}."), 400
    if not recipients:
        return jsonify(error="Informe ao menos um destinatário."), 400
    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(error=f"No máximo {MAX_RECIPIENTS} destinatários por envio."), 400
    if not subject:
        return jsonify(error="Informe o assunto."), 400
    if not body:
        return jsonify(error="Gere o texto do comunicado antes de enviar."), 400

    office = None
    if payload.get("office_id"):
        office = find_office(payload["office_id"])
        if not office:
            return jsonify(error="Ofício não encontrado."), 404

    settings = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    problem = smtp_config_problem(settings)
    if problem:
        return jsonify(error=problem), 400

    try:
        attachments = collect_attachments(office, payload, request.files.getlist("attachments"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    user = current_actor_user()
    record = SentEmail(
        office_id=office.id if office else None,
        office_number=office.office_number if office else None,
        user_id=user.id if user else None,
        recipients=",".join(recipients),
        subject=subject,
        # Guarda o texto exatamente como foi enviado, assinatura incluída.
        body=with_signature(body, settings.email_signature),
        attachments="\n".join(name for name, _ in attachments) or None,
        status="sent",
    )
    try:
        send_email(settings, recipients, subject, body, attachments)
    except Exception as exc:
        record.status = "failed"
        record.error = describe_error(exc)[:1000]
    db.session.add(record)
    if record.status == "sent" and office:
        office.notification_sent_at = datetime.utcnow()
    db.session.commit()

    users_by_id = {user.id: user} if user else {}
    if record.status == "failed":
        return jsonify(error=f"Falha ao enviar o e-mail: {record.error}", email=serialize_sent_email(record, users_by_id)), 502
    return jsonify(email=serialize_sent_email(record, users_by_id)), 201


@api_bp.route("/communications/emails", methods=["GET"])
@require_auth
def list_sent_emails():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 10, type=int), MAX_PER_PAGE)
    pagination = SentEmail.query.order_by(SentEmail.created_at.desc(), SentEmail.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    user_ids = {email.user_id for email in pagination.items if email.user_id}
    users_by_id = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    return jsonify(
        items=[serialize_sent_email(email, users_by_id) for email in pagination.items],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


@api_bp.route("/offices/<int:office_id>/notification", methods=["PUT"])
@require_auth
def set_office_notification(office_id):
    """Marca (sent=true) ou desmarca (sent=false) a notificação do ofício como enviada."""
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404
    payload = request.get_json(silent=True) or {}
    office.notification_sent_at = datetime.utcnow() if payload.get("sent", True) else None
    db.session.commit()
    return jsonify(serialize_office(office))
