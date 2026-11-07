import pytest

from app import create_app, init_database
from app.models import db

LEGACY_SSH_ENV = (
    "SSH_HOST", "SSH_PORT", "SSH_USER", "SSH_PASSWORD", "SSH_KEY_PATH", "SSH_KEY_PASSPHRASE",
    "SSH_STRICT_HOST_KEY_CHECKING", "SUDO_PASSWORD", "RPZ_REMOTE_PATH", "RPZ_RELOAD_COMMAND",
    "RPZ_TEST_RESOLVER", "RPZ_NAMESERVER", "ROUTER_SSH_HOST", "ROUTER_SSH_PORT", "ROUTER_SSH_USER",
    "ROUTER_SSH_PASSWORD", "ROUTER_SSH_KEY_PATH", "ROUTER_SSH_KEY_PASSPHRASE",
    "ABUSE_IMAP_HOST", "ABUSE_IMAP_PORT", "ABUSE_IMAP_USER", "ABUSE_IMAP_PASSWORD", "ABUSE_IMAP_MAILBOX",
)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("DB_CONNECT_ATTEMPTS", "1")
    # Vazias (e não ausentes) para o load_dotenv não trazer a config SSH antiga do .env local.
    for name in LEGACY_SSH_ENV:
        monkeypatch.setenv(name, "")
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            # connect_args do create_app são específicos do PyMySQL.
            "SQLALCHEMY_ENGINE_OPTIONS": {},
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "API_KEY": "",
        }
    )
    init_database(app)
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
