"""Backup automático por FTP: banco (.sql.gz) e anexos (.zip), com retenção no destino.

Quem executa é o ``backup-worker``; a API só grava a configuração, testa a conexão e
pede uma execução imediata (``run_requested_at``).
"""

import ftplib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .backup import write_database_backup, write_files_backup
from .models import BackupSchedule, Deployment, db

DEPLOYMENT_TYPE = "backup-ftp"
FILE_PREFIX = "oficios-rpz"
TEMP_PREFIX = "oficios-backup-"
KINDS = {"banco": "sql.gz", "arquivos": "zip"}
BACKUP_NAME_RE = re.compile(rf"^{FILE_PREFIX}-(?P<kind>banco|arquivos)-\d{{8}}-\d{{6}}\.(?:sql\.gz|zip)$")
RUN_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
# Se o worker estava parado no horário, ainda roda até este tempo depois; mais que isso
# espera o dia seguinte (evita backup no meio do expediente ao ligar o agendamento).
CATCH_UP = timedelta(hours=6)
FTP_TIMEOUT_SECONDS = 60


def local_timezone():
    return ZoneInfo(os.getenv("BACKUP_TIMEZONE", "America/Sao_Paulo"))


def get_backup_schedule():
    schedule = BackupSchedule.query.order_by(BackupSchedule.id).first()
    if schedule is None:
        schedule = BackupSchedule()
        db.session.add(schedule)
        db.session.commit()
    return schedule


def scheduled_utc(schedule, now_utc, zone=None):
    """Horário de hoje (no fuso local) em UTC naive, como o resto do banco."""
    zone = zone or local_timezone()
    hour, minute = (int(part) for part in schedule.run_time.split(":"))
    local_now = now_utc.replace(tzinfo=timezone.utc).astimezone(zone)
    local_run = datetime.combine(local_now.date(), time(hour, minute), tzinfo=zone)
    return local_run.astimezone(timezone.utc).replace(tzinfo=None)


def next_run_utc(schedule, now_utc, zone=None):
    if not schedule.enabled:
        return None
    today = scheduled_utc(schedule, now_utc, zone)
    done_today = schedule.last_attempt_at is not None and schedule.last_attempt_at >= today
    if done_today or now_utc >= today + CATCH_UP:
        return scheduled_utc(schedule, now_utc + timedelta(days=1), zone)
    return today


def is_due(schedule, now_utc, zone=None):
    if schedule.run_requested_at is not None:
        return True
    if not schedule.enabled:
        return False
    run_at = scheduled_utc(schedule, now_utc, zone)
    if not run_at <= now_utc < run_at + CATCH_UP:
        return False
    return schedule.last_attempt_at is None or schedule.last_attempt_at < run_at


def missing_config(schedule):
    if not schedule.ftp_host:
        return "Servidor FTP não configurado."
    if not schedule.include_database and not schedule.include_files:
        return "Nada selecionado para o backup (banco e/ou arquivos)."
    return None


# --- FTP ----------------------------------------------------------------------------

def connect(schedule):
    client = ftplib.FTP_TLS(timeout=FTP_TIMEOUT_SECONDS) if schedule.ftp_tls else ftplib.FTP(timeout=FTP_TIMEOUT_SECONDS)
    client.connect(schedule.ftp_host, schedule.ftp_port or 21)
    client.login(schedule.ftp_user or "anonymous", schedule.ftp_password or "")
    if schedule.ftp_tls:
        client.prot_p()  # canal de dados também criptografado
    client.set_pasv(True)
    change_directory(client, schedule.ftp_directory, create=True)
    return client


def change_directory(client, directory, create=False):
    path = (directory or "").strip()
    if path.startswith("/"):
        client.cwd("/")
    for segment in [part for part in path.split("/") if part]:
        try:
            client.cwd(segment)
        except ftplib.error_perm:
            if not create:
                raise
            client.mkd(segment)
            client.cwd(segment)


def upload(client, local_path, remote_name, write_only=False):
    if write_only:
        # Destino só de gravação (ex.: Pulse Backup): não aceita SIZE, DELE nem renomear
        # depois do envio. Vai direto com o nome final; o 226 do STOR confirma o recebimento.
        with open(local_path, "rb") as handle:
            client.storbinary(f"STOR {remote_name}", handle)
        return
    partial = f"{remote_name}.part"
    with open(local_path, "rb") as handle:
        client.storbinary(f"STOR {partial}", handle)
    expected = Path(local_path).stat().st_size
    try:
        client.voidcmd("TYPE I")
        remote_size = client.size(partial)
    except ftplib.error_perm:
        remote_size = None  # servidor sem SIZE: confia no 226 do STOR
    if remote_size is not None and remote_size != expected:
        raise RuntimeError(f"{remote_name}: enviado com {remote_size} bytes, esperado {expected}.")
    try:
        client.delete(remote_name)
    except ftplib.error_perm:
        pass
    client.rename(partial, remote_name)


def prune(client, keep_count):
    """Mantém só as ``keep_count`` cópias mais recentes de cada tipo. Devolve as apagadas."""
    try:
        names = client.nlst()
    except ftplib.error_perm:
        return []  # alguns servidores respondem 550 para pasta vazia
    by_kind = {}
    for name in names:
        name = name.rsplit("/", 1)[-1]
        match = BACKUP_NAME_RE.match(name)
        if match:
            by_kind.setdefault(match["kind"], []).append(name)
    removed = []
    for kind_names in by_kind.values():
        for name in sorted(kind_names, reverse=True)[keep_count:]:
            client.delete(name)
            removed.append(name)
    return removed


def test_connection(schedule):
    client = connect(schedule)
    try:
        names = [name for name in client.nlst() if BACKUP_NAME_RE.match(name.rsplit("/", 1)[-1])]
    except ftplib.error_perm:
        names = []
    finally:
        close(client)
    return len(names)


def close(client):
    try:
        client.quit()
    except Exception:
        client.close()


# --- execução -----------------------------------------------------------------------

@dataclass
class BackupResult:
    uploaded: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    file_count: int = 0

    def summary(self):
        parts = [f"Enviados: {', '.join(self.uploaded)}"]
        if self.file_count:
            parts.append(f"{self.file_count} anexo(s) no .zip")
        if self.removed:
            parts.append(f"{len(self.removed)} cópia(s) antiga(s) apagada(s)")
        return "; ".join(parts) + "."


def run_backup(schedule, now=None):
    """Gera e envia o backup. Levanta exceção em qualquer falha."""
    problem = missing_config(schedule)
    if problem:
        raise RuntimeError(problem)
    stamp = (now or datetime.now(local_timezone())).strftime("%Y%m%d-%H%M%S")
    result = BackupResult()
    # Nada fica no servidor da aplicação: a pasta temporária some ao sair (com ou sem
    # erro) e cada arquivo é apagado assim que enviado. Sobras de um processo morto no
    # meio são removidas por clean_leftovers() quando o worker inicia.
    with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as work:
        files = []
        if schedule.include_database:
            path = Path(work) / f"{FILE_PREFIX}-banco-{stamp}.{KINDS['banco']}"
            write_database_backup(path)
            files.append(path)
        if schedule.include_files:
            path = Path(work) / f"{FILE_PREFIX}-arquivos-{stamp}.{KINDS['arquivos']}"
            result.file_count = write_files_backup(path)
            files.append(path)
        client = connect(schedule)
        try:
            for path in files:
                upload(client, path, path.name, write_only=schedule.ftp_write_only)
                path.unlink()
                result.uploaded.append(path.name)
            # Só de gravação: não lista nem apaga; a retenção é a do servidor de backup.
            if not schedule.ftp_write_only:
                result.removed = prune(client, schedule.keep_count)
        finally:
            close(client)
    return result


def clean_leftovers(temp_dir=None):
    """Apaga pastas temporárias de backups interrompidos. Devolve quantas removeu."""
    removed = 0
    for path in Path(temp_dir or tempfile.gettempdir()).glob(f"{TEMP_PREFIX}*"):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            removed += 1
    return removed


def execute(logger=None):
    """Uma rodada do worker: roda se estiver na hora ou se foi pedido. Devolve True se rodou."""
    schedule = get_backup_schedule()
    now_utc = datetime.utcnow()
    if not is_due(schedule, now_utc):
        return False
    requested = schedule.run_requested_at is not None
    schedule.run_requested_at = None
    schedule.last_attempt_at = now_utc
    schedule.last_status = "running"
    schedule.last_message = None
    deployment = Deployment(deployment_type=DEPLOYMENT_TYPE, status="running", domain_count=0, ip_count=0)
    db.session.add(deployment)
    db.session.commit()
    deployment_id = deployment.id
    if logger:
        logger.info("Backup FTP iniciando (%s)", "pedido manual" if requested else "agendado")
    try:
        result = run_backup(schedule)
        status, message = "success", result.summary()
    except Exception as exc:  # qualquer falha: não pode deixar o status preso em "running"
        status, message = "error", describe_error(exc)
        if logger and not isinstance(exc, (OSError, EOFError, ftplib.Error, RuntimeError)):
            logger.exception("Falha inesperada no backup FTP")
    db.session.rollback()
    schedule = get_backup_schedule()
    schedule.last_status = status
    schedule.last_message = message[:2000]
    if status == "success":
        schedule.last_success_at = datetime.utcnow()
    deployment = Deployment.query.get(deployment_id) or Deployment(
        deployment_type=DEPLOYMENT_TYPE, domain_count=0, ip_count=0
    )
    deployment.status = status
    deployment.message = message[:2000]
    db.session.add(deployment)
    db.session.commit()
    if logger:
        (logger.info if status == "success" else logger.error)("Backup FTP: %s", message)
    return True


def describe_error(exc):
    text = str(exc).strip()
    if isinstance(exc, ftplib.error_perm) and text.startswith("530"):
        return f"Login FTP recusado: {text}"
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__
