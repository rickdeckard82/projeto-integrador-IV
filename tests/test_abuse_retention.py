"""Retenção: anonimização de incidentes tratados e expurgo do .eml bruto.
Só IPs de documentação e domínios .example."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import app.abuse_worker as abuse_worker
from app.abuse_retention import run_retention, truncate_ip
from app.models import AbuseAuditLog, AbuseIncident, AbuseMessage, CgnatRule, PublicationLock, db
from tests.test_abuse_api import add_message, add_rule, ctx, login  # noqa: F401 - fixtures
from tests.test_abuse_imap import csv_message

NOW = datetime(2026, 12, 1, 12, 0, 0)


@pytest.fixture
def admin(client, ctx):  # noqa: F811
    return login(client)


def handle(incident, when, login_name="cliente01"):
    incident.pppoe_login = login_name
    incident.hubsoft_customer_code = "123"
    incident.action_taken = "Cliente notificado"
    incident.status = "handled"
    incident.handled_at = when
    db.session.commit()


def raw_file(app, message):
    return Path(app.config["UPLOAD_FOLDER"]) / message.raw_path


def test_truncate_ip():
    assert truncate_ip("203.0.113.37") == "203.0.113.0"
    assert truncate_ip("2001:db8:100:5::25") == "2001:db8:100::"


def test_handled_incident_is_anonymized_after_30_days(ctx):  # noqa: F811
    add_rule()
    message = add_message(csv_message(ip="203.0.113.37", port=45380))
    incident = AbuseIncident.query.one()
    assert incident.private_ip == "100.64.22.37"
    handle(incident, NOW - timedelta(days=30, minutes=1))

    stats = run_retention(NOW)
    assert stats.anonymized == 1
    incident = AbuseIncident.query.one()
    assert incident.anonymized_at == NOW
    assert incident.pppoe_login is None and incident.hubsoft_customer_code is None
    assert incident.private_ip is None and incident.source_port is None
    assert incident.public_ip == "203.0.113.0"
    # Fica para estatística:
    assert incident.incident_type == "brute-force"
    assert incident.action_taken == "Cliente notificado"
    assert incident.occurred_at is not None
    entry = AbuseAuditLog.query.filter_by(action="anonymize").one()
    assert entry.user_id is None and entry.incident_id == incident.id
    assert set(json.loads(entry.details)["removed"]) == {"pppoe_login", "hubsoft_customer_code", "private_ip", "source_port"}
    # .eml também sai: todos os incidentes da mensagem estão tratados há mais de 30 dias.
    assert AbuseMessage.query.get(message.id).raw_purged_at == NOW
    assert not raw_file(ctx, message).exists()


@pytest.mark.parametrize("age,expected", [(29, 0), (31, 1)])
def test_discarded_uses_retention_from_discard_time(ctx, age, expected):
    message = add_message(csv_message())
    incident = AbuseIncident.query.one()
    incident.status = "discarded"
    incident.handled_at = NOW - timedelta(days=age)
    incident.pppoe_login = "cliente01"
    db.session.commit()
    stats = run_retention(NOW)
    assert (stats.anonymized, stats.purged) == (expected, expected)
    assert raw_file(ctx, message).exists() == (not expected)


def test_recently_handled_is_kept(ctx):  # noqa: F811
    message = add_message(csv_message())
    handle(AbuseIncident.query.one(), NOW - timedelta(days=29))
    stats = run_retention(NOW)
    assert (stats.anonymized, stats.purged) == (0, 0)
    assert AbuseIncident.query.one().pppoe_login == "cliente01"
    assert raw_file(ctx, message).exists()


@pytest.mark.parametrize("status", ["new", "review", "identified"])
def test_open_incidents_are_never_anonymized(ctx, status):  # noqa: F811
    message = add_message(csv_message())
    incident = AbuseIncident.query.one()
    incident.status = status
    incident.pppoe_login = "cliente01"
    incident.created_at = NOW - timedelta(days=400)
    db.session.commit()
    message.received_at = message.created_at = NOW - timedelta(days=400)
    db.session.commit()
    stats = run_retention(NOW)
    assert (stats.anonymized, stats.purged) == (0, 0)
    assert AbuseIncident.query.one().anonymized_at is None
    assert raw_file(ctx, message).exists()


def test_raw_kept_while_any_incident_of_message_is_open(ctx):  # noqa: F811
    raw = csv_message().replace(
        b"bruteforce\n", b"bruteforce\n2026-10-14T08:01:00+00:00,203.0.113.38,45381,bruteforce\n"
    )
    message = add_message(raw)
    first, second = AbuseIncident.query.order_by(AbuseIncident.id).all()
    handle(first, NOW - timedelta(days=60))
    stats = run_retention(NOW)
    assert (stats.anonymized, stats.purged) == (1, 0)
    assert raw_file(ctx, message).exists()

    handle(second, NOW - timedelta(days=31), login_name="cliente02")
    stats = run_retention(NOW)
    assert (stats.anonymized, stats.purged) == (1, 1)
    assert not raw_file(ctx, message).exists()


def test_message_without_incidents_purged_30_days_after_receipt(ctx):  # noqa: F811
    old = add_message(csv_message("<old@x.example>", ip="198.51.100.9"))  # só terceiros
    new = add_message(csv_message("<new@x.example>", ip="198.51.100.10"))
    old.received_at = old.created_at = NOW - timedelta(days=31)
    new.received_at = new.created_at = NOW - timedelta(days=10)
    db.session.commit()
    stats = run_retention(NOW)
    assert stats.purged == 1
    assert AbuseMessage.query.get(old.id).raw_purged_at == NOW
    assert AbuseMessage.query.get(new.id).raw_purged_at is None
    assert AbuseAuditLog.query.filter_by(action="purge_raw").one().abuse_message_id == old.id


def test_disabled_retention_keeps_everything(ctx):  # noqa: F811
    from app.abuse_services import get_abuse_settings

    settings = get_abuse_settings()
    settings.raw_retention_days = None
    settings.incident_anonymize_days = None
    db.session.commit()
    message = add_message(csv_message())
    handle(AbuseIncident.query.one(), NOW - timedelta(days=999))
    stats = run_retention(NOW)
    assert (stats.anonymized, stats.purged) == (0, 0)
    assert raw_file(ctx, message).exists()
    assert get_abuse_settings().last_retention_run_at == NOW


def test_already_missing_file_is_marked_purged(ctx):  # noqa: F811
    message = add_message(csv_message(ip="198.51.100.9"))
    raw_file(ctx, message).unlink()
    message.received_at = message.created_at = NOW - timedelta(days=40)
    db.session.commit()
    stats = run_retention(NOW)
    assert (stats.purged, stats.missing_files) == (1, 1)


def test_anonymized_incident_is_not_recomputed_or_edited(client, admin):
    add_rule()
    add_message(csv_message(ip="203.0.113.37", port=45380))
    handle(AbuseIncident.query.one(), NOW - timedelta(days=31))
    run_retention(NOW)
    incident = AbuseIncident.query.one()
    # Uma importação nova de CGNAT não devolve o IP privado ao incidente anonimizado.
    from app.abuse_services import recompute_private_ips

    recompute_private_ips()
    db.session.commit()
    assert AbuseIncident.query.one().private_ip is None
    response = client.patch(f"/api/v1/abuse/incidents/{incident.id}", headers=admin, json={"notes": "x"})
    assert response.status_code == 409
    detail = client.get(f"/api/v1/abuse/incidents/{incident.id}", headers=admin).get_json()
    assert detail["anonymized_at"] == NOW.isoformat() + "Z"
    assert detail["message"]["raw_available"] is False
    assert client.get(f"/api/v1/abuse/messages/{incident.abuse_message_id}/raw", headers=admin).status_code == 410


def test_reopening_handled_clears_handled_at(client, admin):
    add_message(csv_message())
    incident = AbuseIncident.query.one()
    url = f"/api/v1/abuse/incidents/{incident.id}"
    client.patch(url, headers=admin, json={"status": "handled", "action_taken": "ok", "pppoe_login": "c1"})
    data = client.patch(url, headers=admin, json={"status": "identified"}).get_json()
    assert data["handled_at"] is None and data["handled_by"] is None
    assert data["identified_at"]


def test_settings_accept_anonymize_days(client, admin):
    data = client.get("/api/v1/abuse/settings", headers=admin).get_json()
    assert (data["raw_retention_days"], data["incident_anonymize_days"]) == (30, 30)
    response = client.put("/api/v1/abuse/settings", headers=admin, json={"incident_anonymize_days": None})
    assert response.status_code == 200 and response.get_json()["incident_anonymize_days"] is None
    assert client.put("/api/v1/abuse/settings", headers=admin, json={"incident_anonymize_days": 0}).status_code == 400


def test_worker_retention_uses_lock(ctx, monkeypatch):  # noqa: F811
    calls = []
    monkeypatch.setattr(abuse_worker, "run_retention", lambda: calls.append(1) or run_retention(NOW))
    assert abuse_worker.retention_once(ctx) is not None
    assert PublicationLock.query.get(abuse_worker.RETENTION_LOCK_NAME) is None
    db.session.add(PublicationLock(name=abuse_worker.RETENTION_LOCK_NAME, owner="outro", acquired_at=datetime.utcnow()))
    db.session.commit()
    assert abuse_worker.retention_once(ctx) is None
    assert calls == [1]


# --- log de auditoria ------------------------------------------------------------------

def test_audit_log_listing_and_filters(client, admin):
    add_message(csv_message())
    incident = AbuseIncident.query.one()
    client.get(f"/api/v1/abuse/incidents/{incident.id}", headers=admin)
    client.patch(f"/api/v1/abuse/incidents/{incident.id}", headers=admin, json={"notes": "conferido"})

    data = client.get(f"/api/v1/abuse/audit?incident={incident.id}", headers=admin).get_json()
    assert [item["action"] for item in data["items"]] == ["update", "view"]
    assert data["items"][0]["user"] == "admin"
    assert data["items"][0]["details"]["changes"]["notes"]["after"] == "conferido"

    assert client.get("/api/v1/abuse/audit?action=update", headers=admin).get_json()["total"] == 1
    assert client.get("/api/v1/abuse/audit?user=sistema", headers=admin).get_json()["total"] == 0
    assert client.get("/api/v1/abuse/audit?action=xpto", headers=admin).status_code == 400
    # A própria consulta ao log fica registrada (a com ação inválida volta 400 antes).
    assert AbuseAuditLog.query.filter_by(action="list_audit").count() == 3


def test_audit_log_requires_access(client, ctx):  # noqa: F811
    headers = login(client, "operador", "senha")
    assert client.get("/api/v1/abuse/audit", headers=headers).status_code == 403
