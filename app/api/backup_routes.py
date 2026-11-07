"""Backup automático por FTP: configuração, teste de conexão e execução imediata."""

from datetime import datetime

from flask import jsonify, request

from ..backup_ftp import (
    RUN_TIME_RE,
    describe_error,
    get_backup_schedule,
    local_timezone,
    missing_config,
    next_run_utc,
    test_connection,
)
from ..models import db
from . import api_bp
from .auth import require_auth
from .routes import iso_utc


def serialize_schedule(schedule):
    return {
        "enabled": schedule.enabled,
        "run_time": schedule.run_time,
        "include_database": schedule.include_database,
        "include_files": schedule.include_files,
        "keep_count": schedule.keep_count,
        "ftp_host": schedule.ftp_host or "",
        "ftp_port": schedule.ftp_port,
        "ftp_user": schedule.ftp_user or "",
        "ftp_password_set": bool(schedule.ftp_password),
        "ftp_directory": schedule.ftp_directory or "",
        "ftp_tls": schedule.ftp_tls,
        "ftp_write_only": schedule.ftp_write_only,
        "run_requested_at": iso_utc(schedule.run_requested_at),
        "last_attempt_at": iso_utc(schedule.last_attempt_at),
        "last_success_at": iso_utc(schedule.last_success_at),
        "last_status": schedule.last_status,
        "last_message": schedule.last_message,
        "next_run_at": iso_utc(next_run_utc(schedule, datetime.utcnow())),
        "timezone": local_timezone().key,
    }


def apply_payload(schedule, payload):
    """Valida e aplica o payload no objeto (sem commit). Levanta ValueError."""
    if "run_time" in payload:
        run_time = str(payload["run_time"] or "").strip()
        if not RUN_TIME_RE.match(run_time):
            raise ValueError("Horário inválido: use HH:MM (ex.: 02:30).")
        schedule.run_time = run_time
    if "keep_count" in payload:
        try:
            keep = int(payload["keep_count"])
        except (TypeError, ValueError) as exc:
            raise ValueError("Cópias mantidas deve ser um número inteiro.") from exc
        if not 1 <= keep <= 365:
            raise ValueError("Cópias mantidas deve estar entre 1 e 365.")
        schedule.keep_count = keep
    if "ftp_port" in payload:
        try:
            port = int(payload["ftp_port"])
        except (TypeError, ValueError) as exc:
            raise ValueError("Porta FTP deve ser um número inteiro.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Porta FTP deve estar entre 1 e 65535.")
        schedule.ftp_port = port
    for key in ("ftp_host", "ftp_user", "ftp_directory"):
        if key in payload:
            setattr(schedule, key, str(payload[key] or "").strip() or None)
    # Senha só muda quando enviada; "clear_ftp_password" apaga a atual.
    if payload.get("ftp_password"):
        schedule.ftp_password = str(payload["ftp_password"])
    elif payload.get("clear_ftp_password"):
        schedule.ftp_password = None
    for key in ("enabled", "include_database", "include_files", "ftp_tls", "ftp_write_only"):
        if key in payload:
            setattr(schedule, key, bool(payload[key]))
    if schedule.enabled and missing_config(schedule):
        raise ValueError(missing_config(schedule))


@api_bp.route("/backup/schedule", methods=["GET"])
@require_auth
def get_backup_schedule_route():
    return jsonify(serialize_schedule(get_backup_schedule()))


@api_bp.route("/backup/schedule", methods=["PUT"])
@require_auth
def update_backup_schedule_route():
    schedule = get_backup_schedule()
    try:
        apply_payload(schedule, request.get_json(silent=True) or {})
    except ValueError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400
    db.session.commit()
    return jsonify(serialize_schedule(schedule))


@api_bp.route("/backup/schedule/test", methods=["POST"])
@require_auth
def test_backup_schedule_route():
    """Testa com os dados do formulário (ainda não salvos) sem gravar nada."""
    schedule = get_backup_schedule()
    try:
        apply_payload(schedule, {**(request.get_json(silent=True) or {}), "enabled": False})
        if not schedule.ftp_host:
            raise ValueError("Servidor FTP não configurado.")
        existing = test_connection(schedule)
        write_only = schedule.ftp_write_only  # lido antes do rollback (que volta ao salvo)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Falha na conexão: {describe_error(exc)}"), 502
    finally:
        db.session.rollback()
    if write_only:
        return jsonify(message="Conexão OK. Destino só de gravação: as cópias antigas ficam no servidor de backup.")
    return jsonify(message=f"Conexão OK. {existing} backup(s) desta aplicação na pasta.")


@api_bp.route("/backup/schedule/run", methods=["POST"])
@require_auth
def run_backup_schedule_route():
    schedule = get_backup_schedule()
    problem = missing_config(schedule)
    if problem:
        return jsonify(error=problem), 400
    schedule.run_requested_at = datetime.utcnow()
    db.session.commit()
    return jsonify(serialize_schedule(schedule)), 202
