from sqlalchemy import inspect, text

from app import ensure_schema
from app.models import User, db

ABUSE_TABLES = {
    "cgnat_rule",
    "abuse_mailbox_state",
    "abuse_message",
    "abuse_incident",
    "abuse_audit_log",
    "abuse_settings",
}


def test_abuse_tables_created(app):
    with app.app_context():
        tables = set(inspect(db.engine).get_table_names())
    assert ABUSE_TABLES <= tables


def test_initial_admin_has_abuse_access(app):
    with app.app_context():
        assert User.query.filter_by(username="admin").one().abuse_access is True


def test_new_user_defaults_without_abuse_access(app):
    with app.app_context():
        user = User(username="operador")
        user.set_password("x")
        db.session.add(user)
        db.session.commit()
        assert user.abuse_access is False


def test_ensure_schema_is_idempotent(app):
    with app.app_context():
        ensure_schema()
        ensure_schema()
        columns = {c["name"] for c in inspect(db.engine).get_columns("user")}
    assert "abuse_access" in columns


def test_ensure_schema_adds_abuse_access_to_legacy_user_table(app):
    """Banco antigo (sem a coluna): só o admin inicial recebe acesso."""
    with app.app_context():
        operator = User(username="operador")
        operator.set_password("x")
        db.session.add(operator)
        db.session.commit()

        db.session.execute(text("ALTER TABLE user DROP COLUMN abuse_access"))
        db.session.commit()
        db.session.expire_all()

        ensure_schema()

        rows = dict(db.session.execute(text("SELECT username, abuse_access FROM user")).all())
    assert bool(rows["admin"]) is True
    assert bool(rows["operador"]) is False
