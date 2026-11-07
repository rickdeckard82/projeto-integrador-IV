import logging
import os
import signal
import time

from flask import current_app
from sqlalchemy import inspect

from . import create_app, wait_for_database
from .backup_ftp import clean_leftovers, execute
from .models import db
from .services import acquire_publish_lock, release_publish_lock

LOCK_NAME = "backup-ftp"
LOCK_OWNER = "backup-worker"

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
    # Curto para "Executar agora" responder logo; a rodada só consulta uma linha.
    interval = int(os.getenv("BACKUP_WORKER_INTERVAL_SECONDS", "30"))

    with app.app_context():
        app.logger.info("Worker de backup iniciando; aguardando banco e estrutura de tabelas")
        wait_for_database()
        wait_for_schema(interval)
        leftovers = clean_leftovers()
        if leftovers:
            app.logger.warning("Removida(s) %s pasta(s) temporária(s) de backup interrompido", leftovers)
        app.logger.info("Worker de backup iniciado (intervalo %ss)", interval)
        while running:
            try:
                run_once(app)
            except Exception:
                app.logger.exception("Falha no loop do worker de backup")
                db.session.rollback()
            finally:
                db.session.remove()
            sleep(interval)
        app.logger.info("Worker de backup finalizado")


def run_once(app):
    if not acquire_publish_lock(LOCK_NAME, owner=LOCK_OWNER):
        return False
    try:
        return execute(app.logger)
    finally:
        release_publish_lock(LOCK_NAME)


def sleep(seconds):
    deadline = time.monotonic() + seconds
    while running and time.monotonic() < deadline:
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def wait_for_schema(interval):
    while running:
        if "backup_schedule" in inspect(db.engine).get_table_names():
            return
        current_app.logger.info("Aguardando criação da tabela backup_schedule pela API")
        sleep(min(interval, 10))


if __name__ == "__main__":
    main()
