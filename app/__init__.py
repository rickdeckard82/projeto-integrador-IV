import os
import re
import time
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from .models import IpBatch, OfficeFile, ParameterSettings, UploadBatch, User, db
from .ssh_settings import dump_targets, has_legacy_env, legacy_env_targets, load_targets


def create_app(test_config=None):
    load_dotenv()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        minutes=int(os.getenv("SESSION_LIFETIME_MINUTES", "60"))
    )
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE_SECONDS", "1800")),
        "connect_args": {
            "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT_SECONDS", "10")),
            "read_timeout": int(os.getenv("DB_READ_TIMEOUT_SECONDS", "20")),
            "write_timeout": int(os.getenv("DB_WRITE_TIMEOUT_SECONDS", "20")),
        },
    }
    app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "/app/uploads")
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024
    app.config["WHOIS_LOOKUP_TIMEOUT_SECONDS"] = int(os.getenv("WHOIS_LOOKUP_TIMEOUT_SECONDS", "8"))
    app.config["WHOIS_WORKER_INTERVAL_SECONDS"] = int(
        os.getenv("WHOIS_WORKER_INTERVAL_SECONDS", "5")
    )
    app.config["WHOIS_WORKER_MAX_ATTEMPTS"] = int(os.getenv("WHOIS_WORKER_MAX_ATTEMPTS", "3"))
    app.config["PUBLISH_LOCK_TIMEOUT_MINUTES"] = int(os.getenv("PUBLISH_LOCK_TIMEOUT_MINUTES", "30"))
    app.config["API_KEY"] = os.getenv("API_KEY", "")

    if test_config:
        app.config.update(test_config)

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

    db.init_app(app)

    from .api import api_bp

    app.register_blueprint(api_bp)

    return app


def init_database(app):
    with app.app_context():
        wait_for_database()
        db.create_all()
        ensure_schema()
        ensure_admin_user()


def ensure_admin_user():
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD")

    if not User.query.filter_by(username=username).first():
        if not password:
            raise RuntimeError("Defina ADMIN_PASSWORD no .env para criar o usuário administrador inicial.")
        user = User(username=username, abuse_access=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def ensure_schema():
    inspector = inspect(db.engine)
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    if "active" not in user_columns:
        db.session.execute(text("ALTER TABLE user ADD COLUMN active BOOL NOT NULL DEFAULT TRUE"))
        db.session.commit()
    if "session_token" not in user_columns:
        db.session.execute(text("ALTER TABLE user ADD COLUMN session_token VARCHAR(64) NULL"))
        db.session.commit()
    if "api_token_hash" not in user_columns:
        db.session.execute(text("ALTER TABLE user ADD COLUMN api_token_hash VARCHAR(64) NULL"))
        db.session.commit()
    if "abuse_access" not in user_columns:
        db.session.execute(
            text("ALTER TABLE user ADD COLUMN abuse_access BOOL NOT NULL DEFAULT FALSE")
        )
        # Só o administrador inicial recebe acesso; os demais são liberados em Usuários.
        db.session.execute(
            text("UPDATE user SET abuse_access = TRUE WHERE username = :username"),
            {"username": os.getenv("ADMIN_USERNAME", "admin")},
        )
        db.session.commit()

    user_unique_columns = {
        tuple(index["column_names"])
        for index in inspector.get_indexes("user")
        if index.get("unique")
    }
    if ("api_token_hash",) not in user_unique_columns:
        db.session.execute(
            text("CREATE UNIQUE INDEX ix_user_api_token_hash ON user (api_token_hash)")
        )
        db.session.commit()

    upload_columns = {column["name"] for column in inspector.get_columns("upload_batch")}
    if "created_by_user_id" not in upload_columns:
        db.session.execute(text("ALTER TABLE upload_batch ADD COLUMN created_by_user_id INTEGER NULL"))
        db.session.commit()
    if "process_number" not in upload_columns:
        db.session.execute(text("ALTER TABLE upload_batch ADD COLUMN process_number VARCHAR(25) NULL"))
        db.session.execute(text("CREATE INDEX ix_upload_batch_process_number ON upload_batch (process_number)"))
        db.session.commit()
    if "sei_numbers" not in upload_columns:
        db.session.execute(text("ALTER TABLE upload_batch ADD COLUMN sei_numbers TEXT NULL"))
        db.session.commit()
    if "expedition_date" not in upload_columns:
        db.session.execute(text("ALTER TABLE upload_batch ADD COLUMN expedition_date DATE NULL"))
        db.session.commit()
    if "office_key" not in upload_columns:
        db.session.execute(text("ALTER TABLE upload_batch ADD COLUMN office_key VARCHAR(160) NULL"))
        db.session.execute(text("CREATE INDEX ix_upload_batch_office_key ON upload_batch (office_key)"))
        db.session.commit()

    if "notification_sent_at" not in upload_columns:
        db.session.execute(text("ALTER TABLE upload_batch ADD COLUMN notification_sent_at DATETIME NULL"))
        db.session.commit()

    table_names = set(inspector.get_table_names())
    if "office_file" in table_names:
        office_file_columns = {column["name"] for column in inspector.get_columns("office_file")}
        if "removal_date" not in office_file_columns:
            db.session.execute(text("ALTER TABLE office_file ADD COLUMN removal_date DATE NULL"))
            db.session.commit()

    if "office_domain" in table_names:
        office_domain_columns = {column["name"] for column in inspector.get_columns("office_domain")}
        if "removal_date" not in office_domain_columns:
            db.session.execute(text("ALTER TABLE office_domain ADD COLUMN removal_date DATE NULL"))
            db.session.commit()

    if "deployment" in table_names:
        deployment_columns = {column["name"] for column in inspector.get_columns("deployment")}
        if "deployment_type" not in deployment_columns:
            db.session.execute(
                text("ALTER TABLE deployment ADD COLUMN deployment_type VARCHAR(30) NOT NULL DEFAULT 'rpz'")
            )
            db.session.commit()
        if "user_id" not in deployment_columns:
            db.session.execute(text("ALTER TABLE deployment ADD COLUMN user_id INTEGER NULL"))
            db.session.commit()
        if "ip_count" not in deployment_columns:
            db.session.execute(text("ALTER TABLE deployment ADD COLUMN ip_count INTEGER NOT NULL DEFAULT 0"))
            db.session.commit()

    if "company_settings" in table_names:
        company_columns = {column["name"] for column in inspector.get_columns("company_settings")}
        company_address_columns = {
            "address_street": "VARCHAR(180)",
            "address_number": "VARCHAR(30)",
            "address_complement": "VARCHAR(120)",
            "address_neighborhood": "VARCHAR(120)",
            "address_city": "VARCHAR(120)",
            "address_state": "VARCHAR(2)",
            "address_zip": "VARCHAR(20)",
        }
        for column_name, column_type in company_address_columns.items():
            if column_name not in company_columns:
                db.session.execute(
                    text(f"ALTER TABLE company_settings ADD COLUMN {column_name} {column_type} NULL")
                )
                db.session.commit()

    if "parameter_settings" in table_names:
        parameter_columns = {column["name"] for column in inspector.get_columns("parameter_settings")}
        new_parameter_columns = {
            "publish_routers": "TEXT",
            "router_command_ipv4": "TEXT",
            "router_command_ipv6": "TEXT",
            "rpz_servers": "TEXT",
            "rpz_nameserver": "VARCHAR(253)",
            "ssh_strict_host_key_checking": "BOOL",
            "smtp_host": "VARCHAR(253)",
            "smtp_port": "INTEGER",
            "smtp_security": "VARCHAR(10)",
            "smtp_user": "VARCHAR(255)",
            "smtp_password": "VARCHAR(255)",
            "smtp_from_email": "VARCHAR(255)",
            "smtp_from_name": "VARCHAR(160)",
            "email_signature": "TEXT",
            "imap_host": "VARCHAR(253)",
            "imap_port": "INTEGER",
            "imap_user": "VARCHAR(255)",
            "imap_password": "VARCHAR(255)",
            "imap_mailbox": "VARCHAR(255)",
        }
        for column_name, column_type in new_parameter_columns.items():
            if column_name not in parameter_columns:
                db.session.execute(
                    text(f"ALTER TABLE parameter_settings ADD COLUMN {column_name} {column_type} NULL")
                )
                db.session.commit()

    if "ip_batch" in table_names:
        ip_columns = {column["name"] for column in inspector.get_columns("ip_batch")}
        if "office_id" not in ip_columns:
            db.session.execute(text("ALTER TABLE ip_batch ADD COLUMN office_id INTEGER NULL"))
            db.session.execute(text("CREATE INDEX ix_ip_batch_office_id ON ip_batch (office_id)"))
            db.session.commit()
            ip_columns.add("office_id")
        if "office_key" not in ip_columns:
            db.session.execute(text("ALTER TABLE ip_batch ADD COLUMN office_key VARCHAR(160) NULL"))
            db.session.execute(text("CREATE INDEX ix_ip_batch_office_key ON ip_batch (office_key)"))
            db.session.commit()
        if "expedition_date" not in ip_columns:
            db.session.execute(text("ALTER TABLE ip_batch ADD COLUMN expedition_date DATE NULL"))
            db.session.commit()
        if "removal_date" not in ip_columns:
            db.session.execute(text("ALTER TABLE ip_batch ADD COLUMN removal_date DATE NULL"))
            db.session.commit()

    if "domain" in table_names:
        domain_columns = {column["name"] for column in inspector.get_columns("domain")}
        if "redirect_target" not in domain_columns:
            db.session.execute(text("ALTER TABLE domain ADD COLUMN redirect_target VARCHAR(253) NULL"))
            db.session.commit()

    if "sent_email" in table_names:
        sent_email_columns = {column["name"] for column in inspector.get_columns("sent_email")}
        if "attachments" not in sent_email_columns:
            db.session.execute(text("ALTER TABLE sent_email ADD COLUMN attachments TEXT NULL"))
            db.session.commit()

    if "backup_schedule" in table_names:
        backup_columns = {column["name"] for column in inspector.get_columns("backup_schedule")}
        if "ftp_write_only" not in backup_columns:
            db.session.execute(
                text("ALTER TABLE backup_schedule ADD COLUMN ftp_write_only BOOL NOT NULL DEFAULT FALSE")
            )
            db.session.commit()

    ensure_office_keys()
    ensure_legacy_office_files()
    import_legacy_ssh_settings()
    import_legacy_imap_settings()


def import_legacy_imap_settings():
    """Copia a caixa de abuse do .env (ABUSE_IMAP_*) para Parâmetros, uma única vez
    (enquanto o servidor IMAP nunca foi salvo)."""
    settings = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    host = (os.getenv("ABUSE_IMAP_HOST") or "").strip()
    if (settings and settings.imap_host is not None) or not host:
        return
    if not settings:
        settings = ParameterSettings()
        db.session.add(settings)

    try:
        port = int(os.getenv("ABUSE_IMAP_PORT") or 993)
    except ValueError:
        port = 993
    settings.imap_host = host
    settings.imap_port = port
    settings.imap_user = (os.getenv("ABUSE_IMAP_USER") or "").strip() or None
    settings.imap_password = os.getenv("ABUSE_IMAP_PASSWORD") or None
    settings.imap_mailbox = (os.getenv("ABUSE_IMAP_MAILBOX") or "").strip() or None
    db.session.commit()


def import_legacy_ssh_settings():
    """Copia BIND, credenciais dos roteadores e servidor de nomes do .env para
    Parâmetros, uma única vez (enquanto os servidores BIND nunca foram salvos)."""
    settings = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    if (settings and settings.rpz_servers is not None) or not has_legacy_env():
        return
    if not settings:
        settings = ParameterSettings()
        db.session.add(settings)

    servers, routers, strict = legacy_env_targets(load_targets(settings.publish_routers, "router"))
    settings.rpz_servers = dump_targets(servers)
    settings.publish_routers = dump_targets(routers)
    settings.ssh_strict_host_key_checking = strict
    settings.rpz_nameserver = settings.rpz_nameserver or (os.getenv("RPZ_NAMESERVER") or "").strip() or None
    db.session.commit()


def ensure_office_keys():
    changed = False
    for batch in UploadBatch.query.filter(UploadBatch.office_key.is_(None)).all():
        batch.office_key = normalize_office_key(batch.office_number)
        changed = True
    for batch in IpBatch.query.filter(IpBatch.office_key.is_(None)).all():
        batch.office_key = normalize_office_key(batch.name)
        changed = True
    if changed:
        db.session.commit()


def normalize_office_key(value):
    return re.sub(r"[^0-9a-z]+", "", (value or "").lower())


def ensure_legacy_office_files():
    existing = db.session.query(OfficeFile.id).first()
    if existing:
        return

    batches = UploadBatch.query.filter(UploadBatch.stored_filename.isnot(None)).all()
    for batch in batches:
        if batch.stored_filename.startswith("manual-"):
            continue
        db.session.add(
            OfficeFile(
                office_id=batch.id,
                file_type="import",
                filename=batch.filename,
                stored_filename=batch.stored_filename,
            )
        )
    db.session.commit()


def wait_for_database():
    attempts = int(os.getenv("DB_CONNECT_ATTEMPTS", "30"))
    delay = int(os.getenv("DB_CONNECT_DELAY_SECONDS", "2"))

    for attempt in range(1, attempts + 1):
        try:
            with db.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return
        except OperationalError:
            if attempt == attempts:
                raise
            time.sleep(delay)
