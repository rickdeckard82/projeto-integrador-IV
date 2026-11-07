import logging
import os
import signal
import time
from datetime import datetime

from flask import current_app
from sqlalchemy import inspect

from . import create_app, wait_for_database
from .abuse_imap import ImapConfig, ReadOnlyMailbox, collect, connect
from .abuse_retention import run_retention
from .models import AbuseMailboxState, ParameterSettings, db
from .services import acquire_publish_lock, release_publish_lock

LOCK_NAME = "abuse-imap"
RETENTION_LOCK_NAME = "abuse-retention"
LOCK_OWNER = "abuse-worker"
RETENTION_INTERVAL_SECONDS = 24 * 60 * 60

running = True


def stop_worker(signum, frame):
    global running
    running = False


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGINT, stop_worker)
    signal.signal(signal.SIGTERM, stop_worker)

    app = create_app()
    app.logger.setLevel(logging.INFO)
    interval = int(os.getenv("ABUSE_POLL_INTERVAL_SECONDS", "600"))
    max_parse_bytes = int(os.getenv("ABUSE_MAX_MESSAGE_MB", "25")) * 1024 * 1024

    with app.app_context():
        app.logger.info("Worker de abuse iniciando; aguardando banco e estrutura de tabelas")
        wait_for_database()
        wait_for_schema(interval)
        app.logger.info("Worker de abuse iniciado (intervalo %ss)", interval)
        last_config = False

        last_retention = None
        while running:
            if last_retention is None or time.monotonic() - last_retention >= RETENTION_INTERVAL_SECONDS:
                try:
                    retention_once(app)
                    last_retention = time.monotonic()
                except Exception:
                    app.logger.exception("Falha na retenção do módulo de abuse")
                    db.session.rollback()
                finally:
                    db.session.remove()
            # Relida a cada rodada: mudanças em Geral > Parâmetros valem sem reiniciar.
            try:
                config = load_config()
            except Exception:
                app.logger.exception("Falha ao ler a configuração da caixa de abuse")
                db.session.rollback()
                config = None
            finally:
                db.session.remove()
            if config != last_config:
                if config is None:
                    app.logger.warning("Servidor IMAP não configurado em Parâmetros: coleta de abuse desativada")
                else:
                    app.logger.info("Coleta de abuse: %s, caixa %s", config.host, config.mailbox)
                last_config = config
            if config is not None:
                try:
                    run_once(app, config, max_parse_bytes)
                except Exception:
                    app.logger.exception("Falha no loop do worker de abuse")
                    db.session.rollback()
                finally:
                    db.session.remove()
            sleep(interval)

        app.logger.info("Worker de abuse finalizado")


def load_config():
    settings = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    return ImapConfig.from_settings(settings)


def run_once(app, config, max_parse_bytes):
    if not acquire_publish_lock(LOCK_NAME, owner=LOCK_OWNER):
        app.logger.info("Coleta de abuse já em andamento; pulando esta rodada")
        return None
    connection = None
    try:
        app.logger.info("Iniciando coleta de abuse (%s, caixa %s)", config.host, config.mailbox)
        connection = connect(config)
        mailbox = ReadOnlyMailbox(connection, config.mailbox)
        stats = collect(mailbox, config.mailbox, max_parse_bytes=max_parse_bytes)
        app.logger.info(
            "Coleta de abuse: %s lidas, %s novas, %s duplicadas, %s com erro, %s incidentes, último UID %s%s",
            stats.fetched,
            stats.created,
            stats.duplicates,
            stats.errors,
            stats.incidents,
            stats.last_uid,
            f" (interrompida: {stats.failure})" if stats.failure else "",
        )
        return stats
    except Exception as exc:
        record_connection_error(config.mailbox, exc)
        raise
    finally:
        if connection is not None:
            try:
                connection.logout()
            except Exception:
                pass
        release_publish_lock(LOCK_NAME)


def retention_once(app):
    if not acquire_publish_lock(RETENTION_LOCK_NAME, owner=LOCK_OWNER):
        return None
    try:
        stats = run_retention()
        app.logger.info(
            "Retenção de abuse: %s incidente(s) anonimizado(s), %s .eml apagado(s)%s",
            stats.anonymized,
            stats.purged,
            f", erros: {'; '.join(stats.errors)}" if stats.errors else "",
        )
        return stats
    finally:
        release_publish_lock(RETENTION_LOCK_NAME)


def record_connection_error(mailbox_name, exc):
    db.session.rollback()
    state = AbuseMailboxState.query.filter_by(mailbox=mailbox_name).first()
    if state is None:
        state = AbuseMailboxState(mailbox=mailbox_name, last_uid=0)
        db.session.add(state)
    state.last_run_at = datetime.utcnow()
    # Nunca grava a senha: a mensagem do imaplib não a contém, mas limita o tamanho.
    state.last_error = f"{type(exc).__name__}: {exc}"[:2000]
    db.session.commit()


def sleep(seconds):
    deadline = time.monotonic() + seconds
    while running and time.monotonic() < deadline:
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def wait_for_schema(interval):
    while running:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        # Os campos IMAP de Parâmetros são criados pela API (ensure_schema).
        if "abuse_mailbox_state" in tables and "parameter_settings" in tables and "imap_host" in {
            column["name"] for column in inspector.get_columns("parameter_settings")
        }:
            return
        current_app.logger.info("Aguardando a API criar as tabelas e campos do módulo de abuse")
        sleep(min(interval, 10))


if __name__ == "__main__":
    main()
