"""Rotas do módulo de abuse: acesso, auditoria, transições e regras de CGNAT.
Só IPs de documentação e domínios .example."""

import io
import json
from datetime import datetime

import pytest

from app.abuse_services import get_abuse_settings, ingest_raw_message
from app.models import AbuseAuditLog, AbuseIncident, AbuseMessage, CgnatRule, User, db
from tests.test_abuse_imap import csv_message
from tests.test_cgnat_import import a10_file

OWN = ["203.0.113.0/24", "2001:db8:100::/48"]


@pytest.fixture
def ctx(app):
    with app.app_context():
        settings = get_abuse_settings()
        settings.own_prefixes = json.dumps(OWN)
        user = User(username="operador")
        user.set_password("senha")
        db.session.add(user)
        db.session.commit()
        yield app


def login(client, username="admin", password="admin"):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.get_json()
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


@pytest.fixture
def admin(client, ctx):
    return login(client)


@pytest.fixture
def operator(client, ctx):
    return login(client, "operador", "senha")


def add_message(raw):
    outcome = ingest_raw_message(raw)
    db.session.commit()
    return outcome.message


def add_rule(public="203.0.113.0/24", private="100.64.0.0/19", valid_from=datetime(2026, 1, 1)):
    rule = CgnatRule(
        private_prefix=private,
        public_prefix=public,
        ports_per_subscriber=2016,
        first_port=1024,
        allocation="interleaved",
        valid_from=valid_from,
        import_group=f"g-{public}-{valid_from:%Y%m%d}",
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def actions():
    return [entry.action for entry in AbuseAuditLog.query.order_by(AbuseAuditLog.id)]


# --- acesso ------------------------------------------------------------------------

def test_user_without_access_gets_403(client, operator):
    for path in ("/abuse/status", "/abuse/incidents", "/abuse/messages", "/abuse/settings", "/abuse/cgnat-rules"):
        assert client.get(f"/api/v1{path}", headers=operator).status_code == 403


def test_service_api_key_is_refused(client, ctx):
    ctx.config["API_KEY"] = "chave-de-servico"
    response = client.get("/api/v1/abuse/incidents", headers={"X-API-Key": "chave-de-servico"})
    assert response.status_code == 403
    assert "API key" in response.get_json()["error"]


def test_anonymous_gets_401_or_503(client, ctx):
    assert client.get("/api/v1/abuse/incidents").status_code in (401, 503)


def test_me_and_users_expose_abuse_access(client, admin):
    assert client.get("/api/v1/auth/me", headers=admin).get_json()["abuse_access"] is True
    users = {u["username"]: u for u in client.get("/api/v1/users", headers=admin).get_json()["items"]}
    assert users["admin"]["abuse_access"] is True
    assert users["operador"]["abuse_access"] is False


def test_only_abuse_users_grant_access_and_it_is_audited(client, admin, operator):
    target = User.query.filter_by(username="operador").one()
    assert client.post(f"/api/v1/abuse/users/{target.id}/access", headers=operator,
                       json={"abuse_access": True}).status_code == 403
    response = client.post(f"/api/v1/abuse/users/{target.id}/access", headers=admin, json={"abuse_access": True})
    assert response.status_code == 200 and response.get_json()["abuse_access"] is True
    assert actions() == ["access_grant"]


def test_cannot_revoke_last_access_holder(client, admin):
    me = User.query.filter_by(username="admin").one()
    response = client.post(f"/api/v1/abuse/users/{me.id}/access", headers=admin, json={"abuse_access": False})
    assert response.status_code == 400


def test_password_of_abuse_user_protected_from_other_users(client, admin, operator):
    me = User.query.filter_by(username="admin").one()
    response = client.post(f"/api/v1/users/{me.id}/password", headers=operator, json={"password": "x"})
    assert response.status_code == 403
    other = User.query.filter_by(username="operador").one()
    assert client.post(f"/api/v1/users/{other.id}/password", headers=admin, json={"password": "y"}).status_code == 200


def test_cannot_deactivate_last_abuse_user(client, admin, ctx):
    extra = User(username="outro")
    extra.set_password("z")
    db.session.add(extra)
    db.session.commit()
    headers = login(client, "outro", "z")
    me = User.query.filter_by(username="admin").one()
    response = client.post(f"/api/v1/users/{me.id}/toggle", headers=headers)
    assert response.status_code == 400
    assert "abuse" in response.get_json()["error"]


# --- incidentes ----------------------------------------------------------------------

def test_list_and_detail_are_audited(client, admin):
    add_rule()
    message = add_message(csv_message(ip="203.0.113.37", port=45380))
    listing = client.get("/api/v1/abuse/incidents", headers=admin).get_json()
    assert listing["total"] == 1
    row = listing["items"][0]
    assert (row["public_ip"], row["private_ip"], row["status"]) == ("203.0.113.37", "100.64.22.37", "new")
    assert row["recurrence"] == {"customer": 0, "private_ip": 0}

    detail = client.get(f"/api/v1/abuse/incidents/{row['id']}", headers=admin).get_json()
    assert detail["public_kind"] == "cgnat"
    assert detail["port_block"] == {"start": 45376, "end": 47391, "block": 22}
    assert detail["lookup_window"] == {
        "minutes": 5,
        "start": "2026-10-14T07:55:00Z",
        "end": "2026-10-14T08:05:00Z",
    }
    assert detail["session_resolver"] == "manual" and detail["sessions"] == []
    assert detail["message"]["id"] == message.id
    assert actions() == ["list", "view"]
    view = AbuseAuditLog.query.filter_by(action="view").one()
    assert view.incident_id == row["id"] and view.abuse_message_id == message.id
    assert view.user_id == User.query.filter_by(username="admin").one().id


def test_dedicated_and_ipv6_kinds(client, admin):
    add_rule(public="203.0.113.0/25", private="100.64.0.0/20")  # só metade do /24 é CGNAT
    add_message(csv_message("<a@x.example>", ip="2001:db8:100::9"))
    add_message(csv_message("<b@x.example>", ip="203.0.113.250"))
    add_message(csv_message("<c@x.example>", ip="203.0.113.5", port=1000))  # porta abaixo da inicial
    kinds = {}
    for item in AbuseIncident.query.all():
        kinds[item.public_ip] = client.get(f"/api/v1/abuse/incidents/{item.id}", headers=admin).get_json()
    assert kinds["2001:db8:100::9"]["public_kind"] == "ipv6"
    assert kinds["203.0.113.250"]["public_kind"] == "dedicated"
    assert kinds["203.0.113.5"]["public_kind"] == "cgnat"
    assert kinds["203.0.113.5"]["private_ip"] is None


def test_filters(client, admin):
    add_message(csv_message("<a@x.example>", ip="203.0.113.1"))
    add_message(csv_message("<b@x.example>", ip="203.0.113.2", when="2026-10-14 08:00:00"))
    get = lambda query: client.get(f"/api/v1/abuse/incidents?{query}", headers=admin).get_json()
    assert get("status=new")["total"] == 1
    assert get("status=review")["total"] == 1
    assert get("q=203.0.113.2")["total"] == 1
    assert get("type=brute-force")["total"] == 2
    # Sem horário do incidente, o filtro de data usa a data de registro (agora).
    assert get("to=2026-10-14T09:00:00Z")["total"] == 1
    assert get("from=2099-01-01T00:00:00Z")["total"] == 0
    assert client.get("/api/v1/abuse/incidents?status=xpto", headers=admin).status_code == 400


def test_status_transitions(client, admin):
    add_message(csv_message())
    incident = AbuseIncident.query.one()
    url = f"/api/v1/abuse/incidents/{incident.id}"

    response = client.patch(url, headers=admin, json={"status": "identified"})
    assert response.status_code == 400
    response = client.patch(url, headers=admin, json={"status": "identified", "pppoe_login": "cliente01"})
    data = response.get_json()
    assert response.status_code == 200
    assert data["status"] == "identified" and data["identified_by"]["username"] == "admin"
    assert data["identified_at"]

    assert client.patch(url, headers=admin, json={"status": "handled"}).status_code == 400
    data = client.patch(
        url, headers=admin, json={"status": "handled", "action_taken": "Cliente notificado", "hubsoft_customer_code": "123"}
    ).get_json()
    assert data["status"] == "handled" and data["handled_by"]["username"] == "admin"
    assert data["hubsoft_customer_code"] == "123"

    updates = AbuseAuditLog.query.filter_by(action="update").all()
    assert len(updates) == 2
    changes = json.loads(updates[1].details)["changes"]
    assert changes["status"] == {"before": "identified", "after": "handled"}
    assert changes["action_taken"]["after"] == "Cliente notificado"
    assert "view" not in actions()  # PATCH não registra visualização falsa


def test_patch_rejects_invalid_values(client, admin):
    add_message(csv_message())
    incident = AbuseIncident.query.one()
    url = f"/api/v1/abuse/incidents/{incident.id}"
    assert client.patch(url, headers=admin, json={"status": "fechado"}).status_code == 400
    assert client.patch(url, headers=admin, json={"pppoe_login": 123}).status_code == 400
    assert client.patch(url, headers=admin, json={"pppoe_login": "x" * 121}).status_code == 400


def test_recurrence_by_customer_and_private_ip(client, admin):
    add_rule()
    add_message(csv_message("<a@x.example>", ip="203.0.113.37", port=45380))
    add_message(csv_message("<b@x.example>", ip="203.0.113.37", port=45390, when="2026-10-20T08:00:00+00:00"))
    add_message(csv_message("<c@x.example>", ip="203.0.113.5", port=2000, when="2026-10-21T08:00:00+00:00"))
    first, second, third = AbuseIncident.query.order_by(AbuseIncident.id).all()
    first.pppoe_login = third.pppoe_login = "cliente01"
    db.session.commit()
    detail = client.get(f"/api/v1/abuse/incidents/{first.id}", headers=admin).get_json()
    assert [item["id"] for item in detail["recurrence"]["customer"]] == [third.id]
    assert [item["id"] for item in detail["recurrence"]["private_ip"]] == [second.id]


def test_export_csv(client, admin):
    add_message(csv_message())
    response = client.get("/api/v1/abuse/incidents/export.csv", headers=admin)
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert text.startswith("﻿id;status;tipo")
    assert "203.0.113.37" in text and "alerts@soc.example" in text
    entry = AbuseAuditLog.query.filter_by(action="export_csv").one()
    assert json.loads(entry.details)["count"] == 1


# --- mensagens -------------------------------------------------------------------------

def test_message_detail_shows_plain_text_and_raw_download(client, admin):
    message = add_message(csv_message())
    data = client.get(f"/api/v1/abuse/messages/{message.id}", headers=admin).get_json()
    assert "Attached." in data["body_text"]
    assert data["attachments"][0]["filename"] == "e.csv"
    assert any(h["name"] == "From" for h in data["headers"])
    raw = client.get(f"/api/v1/abuse/messages/{message.id}/raw", headers=admin)
    assert raw.status_code == 200 and raw.data == csv_message()
    assert actions() == ["view_raw", "download_raw"]


def test_purged_raw_returns_410(client, admin):
    message = add_message(csv_message())
    message.raw_purged_at = datetime.utcnow()
    db.session.commit()
    assert client.get(f"/api/v1/abuse/messages/{message.id}/raw", headers=admin).status_code == 410


def test_reprocess_after_configuring_prefixes(client, admin):
    settings = get_abuse_settings()
    settings.own_prefixes = json.dumps([])
    db.session.commit()
    message = add_message(csv_message())
    assert message.status == "unrecognized"
    listing = client.get("/api/v1/abuse/messages?status=unrecognized", headers=admin).get_json()
    assert listing["total"] == 1
    client.put("/api/v1/abuse/settings", headers=admin, json={"own_prefixes": OWN})
    response = client.post(f"/api/v1/abuse/messages/{message.id}/reprocess", headers=admin)
    assert response.status_code == 200 and response.get_json()["status"] == "processed"
    assert AbuseIncident.query.count() == 1
    assert client.post(f"/api/v1/abuse/messages/{message.id}/reprocess", headers=admin).status_code == 400


# --- configurações ---------------------------------------------------------------------

def test_settings_validation_and_audit(client, admin):
    put = lambda body: client.put("/api/v1/abuse/settings", headers=admin, json=body)
    assert put({"own_prefixes": ["não é prefixo"]}).status_code == 400
    assert put({"sender_timezones": {"x.example": "Marte/Base"}}).status_code == 400
    assert put({"lookup_window_minutes": 0}).status_code == 400
    response = put(
        {
            "own_prefixes": ["203.0.113.0/24", "203.0.113.0/24", "2001:db8:100::/48"],
            "sender_timezones": {".Soc.Example": "America/Sao_Paulo"},
            "lookup_window_minutes": 10,
            "raw_retention_days": None,
        }
    )
    data = response.get_json()
    assert response.status_code == 200
    assert data["own_prefixes"] == ["203.0.113.0/24", "2001:db8:100::/48"]
    assert data["sender_timezones"] == {"soc.example": "America/Sao_Paulo"}
    assert data["lookup_window_minutes"] == 10
    entry = AbuseAuditLog.query.filter_by(action="settings_change").one()
    assert set(json.loads(entry.details)["changes"]) == {"sender_timezones", "lookup_window_minutes", "raw_retention_days"}


# --- regras de CGNAT -------------------------------------------------------------------

def upload(client, headers, valid_from, files, dry_run=False):
    data = {
        "valid_from": valid_from,
        "files": [(io.BytesIO(content.encode()), name) for name, content in files],
    }
    if dry_run:
        data["dry_run"] = "1"
    return client.post(
        "/api/v1/abuse/cgnat-rules/import", headers=headers, data=data, content_type="multipart/form-data"
    )


POOL_A = ("pool_a.txt", a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128))
POOL_B = ("pool_b.txt", a10_file("203.0.113.4/30", "100.64.0.16/28", 1024, 16128))


def test_import_dry_run_does_not_save(client, admin):
    response = upload(client, admin, "2026-01-01T03:00:00Z", [POOL_A, POOL_B], dry_run=True)
    data = response.get_json()
    assert response.status_code == 200 and data["dry_run"] is True
    assert [r["public_prefix"] for r in data["rules"]] == ["203.0.113.0/30", "203.0.113.4/30"]
    assert data["pools"][0]["entry_count"] == 16
    assert CgnatRule.query.count() == 0
    assert "rule_change" not in actions()


def test_import_new_validity_closes_previous_and_recalculates(client, admin):
    assert upload(client, admin, "2026-01-01T03:00:00Z", [POOL_A, POOL_B]).status_code == 201
    add_message(csv_message(ip="203.0.113.1", port=1024))
    incident = AbuseIncident.query.one()
    assert incident.private_ip == "100.64.0.1"

    # Nova configuração do equipamento: pool A agora sequencial, a partir de 2026-06-01.
    new_a = ("pool_a_v2.txt", a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128, allocation="sequential"))
    response = upload(client, admin, "2026-06-01T03:00:00Z", [new_a])
    data = response.get_json()
    assert response.status_code == 201
    assert len(data["closings"]) == 1
    assert data["closings"][0]["new_valid_to"] == "2026-06-01T03:00:00Z"
    db.session.expire_all()
    # O incidente é de outubro: passa a usar a regra nova (sequencial).
    assert AbuseIncident.query.one().private_ip == "100.64.0.4"
    assert data["incidents_recalculated"] == 1

    # A importação antiga não pode ser apagada enquanto a nova existir.
    old_group = CgnatRule.query.filter_by(source_filename="pool_a.txt").one().import_group
    assert client.delete(f"/api/v1/abuse/cgnat-rules/groups/{old_group}", headers=admin).status_code == 409

    # Apagar a nova reabre a antiga e recalcula.
    new_group = data["import_group"]
    assert client.delete(f"/api/v1/abuse/cgnat-rules/groups/{new_group}", headers=admin).status_code == 200
    db.session.expire_all()
    reopened = CgnatRule.query.filter_by(source_filename="pool_a.txt").one()
    assert reopened.valid_to is None and reopened.closed_by_group is None
    assert AbuseIncident.query.one().private_ip == "100.64.0.1"
    assert actions().count("rule_change") == 3


def test_import_rejects_bad_file_and_overlap(client, admin):
    assert upload(client, admin, "2026-01-01T03:00:00Z", [("lixo.txt", "nada aqui")]).status_code == 400
    assert upload(client, admin, "", [POOL_A]).status_code == 400
    assert upload(client, admin, "2026-06-01T03:00:00Z", [POOL_A]).status_code == 201
    # Vigência anterior a uma regra em aberto: conflito.
    assert upload(client, admin, "2026-01-01T03:00:00Z", [POOL_A]).status_code == 409


def test_manual_rule(client, admin):
    body = {
        "private_prefix": "100.64.0.0/19",
        "public_prefix": "198.51.100.0/24",
        "ports_per_subscriber": 2016,
        "first_port": 1024,
        "allocation": "sequential",
        "valid_from": "2026-01-01T03:00:00Z",
    }
    assert client.post("/api/v1/abuse/cgnat-rules", headers=admin, json={**body, "allocation": "x"}).status_code == 400
    assert client.post("/api/v1/abuse/cgnat-rules", headers=admin, json={**body, "first_port": 2000}).status_code == 400
    response = client.post("/api/v1/abuse/cgnat-rules", headers=admin, json=body)
    assert response.status_code == 201
    rules = client.get("/api/v1/abuse/cgnat-rules", headers=admin).get_json()["items"]
    assert rules[0]["allocation"] == "sequential" and rules[0]["blocks_per_ip"] == 32


def test_bulk_reprocess_with_cursor(client, admin, monkeypatch):
    import app.api.abuse_routes as abuse_routes

    settings = get_abuse_settings()
    settings.own_prefixes = json.dumps([])
    db.session.commit()
    ours = [add_message(csv_message(f"<m{i}@x.example>", ip=f"203.0.113.{i}")) for i in range(1, 4)]
    third = add_message(csv_message("<t@x.example>", ip="198.51.100.9"))
    assert AbuseMessage.query.filter_by(status="unrecognized").count() == 4
    client.put("/api/v1/abuse/settings", headers=admin, json={"own_prefixes": OWN})

    monkeypatch.setattr(abuse_routes, "BULK_REPROCESS_LIMIT", 2)
    url = "/api/v1/abuse/messages/reprocess"
    first = client.post(url, headers=admin, json={}).get_json()
    assert (first["processed"], first["recognized"], first["remaining"]) == (2, 2, 2)
    second = client.post(url, headers=admin, json={"after_id": first["last_id"]}).get_json()
    assert (second["processed"], second["recognized"], second["remaining"]) == (2, 1, 0)
    # A de terceiros continua não reconhecida e não entra em loop.
    assert AbuseMessage.query.get(third.id).status == "unrecognized"
    assert all(AbuseMessage.query.get(m.id).status == "processed" for m in ours)
    assert AbuseIncident.query.count() == 3
    entries = AbuseAuditLog.query.filter_by(action="reprocess").all()
    assert len(entries) == 2 and json.loads(entries[0].details)["bulk"] is True
    assert client.post(url, headers=admin, json={"statuses": ["processed"]}).status_code == 400


def test_discard_preserves_message_and_audits_selected_only(client, admin):
    record = add_message(csv_message())
    first = AbuseIncident.query.one()
    other = add_message(csv_message("<other@x.example>", ip="203.0.113.38"))
    raw_path = record.raw_path
    url = "/api/v1/abuse/incidents/discard"
    assert client.post(url, headers=admin, json={"ids": [first.id], "reason": " "}).status_code == 400
    assert client.post(url, headers=admin, json={"ids": [first.id, 99999], "reason": "Administrativo"}).status_code == 404
    assert db.session.get(AbuseIncident, first.id).status != "discarded"
    response = client.post(url, headers=admin, json={"ids": [first.id], "reason": "Autorização SNDS"})
    assert response.get_json() == {"discarded": 1}
    assert db.session.get(AbuseMessage, record.id).raw_path == raw_path
    assert AbuseIncident.query.filter_by(abuse_message_id=other.id).one().status != "discarded"
    assert client.get("/api/v1/abuse/incidents", headers=admin).get_json()["total"] == 1
    discarded = client.get("/api/v1/abuse/incidents?status=discarded", headers=admin).get_json()["items"]
    assert [item["id"] for item in discarded] == [first.id]
    assert discarded[0]["discard"]["reason"] == "Autorização SNDS"
    assert discarded[0]["discard"]["by"]["username"] == "admin"
    assert client.post(url, headers=admin, json={"ids": [first.id], "reason": "Repetido"}).get_json() == {"discarded": 0}
    assert AbuseAuditLog.query.filter_by(action="discard").count() == 1
    assert client.patch(f"/api/v1/abuse/incidents/{first.id}", headers=admin, json={"status": "review"}).status_code == 409


def test_bulk_discard_and_access(client, admin, operator):
    for index in range(2):
        add_message(csv_message(f"<discard{index}@x.example>", ip=f"203.0.113.{index + 1}"))
    ids = [item.id for item in AbuseIncident.query.all()]
    url = "/api/v1/abuse/incidents/discard"
    payload = {"ids": ids, "reason": "E-mail administrativo"}
    assert client.post(url, headers=operator, json=payload).status_code == 403
    assert client.post(url, headers=admin, json={"ids": [True], "reason": "Erro"}).status_code == 400
    assert client.post(url, headers=admin, json=payload).get_json() == {"discarded": 2}
    assert AbuseAuditLog.query.filter_by(action="discard").count() == 2


def test_discard_removes_recurrence_and_default_csv(client, admin):
    from app.api.abuse_routes import recurrence

    for index in range(2):
        add_message(csv_message(f"<rec{index}@x.example>", ip=f"203.0.113.{index + 1}"))
    first, second = AbuseIncident.query.order_by(AbuseIncident.id).all()
    first.pppoe_login = second.pppoe_login = "same-customer"
    db.session.commit()
    assert len(recurrence(first, 30)[0]) == 1
    response = client.post("/api/v1/abuse/incidents/discard", headers=admin,
                           json={"ids": [second.id], "reason": "Administrativo"})
    assert response.status_code == 200
    assert recurrence(first, 30) == ([], [])
    assert recurrence(second, 30) == ([], [])
    csv = client.get("/api/v1/abuse/incidents/export.csv", headers=admin).get_data(as_text=True)
    assert second.public_ip not in csv
    assert first.public_ip in csv


def test_restore_discarded_is_audited_and_idempotent(client, admin, operator):
    for index in range(2):
        add_message(csv_message(f"<restore{index}@x.example>", ip=f"203.0.113.{index + 1}"))
    records = AbuseIncident.query.order_by(AbuseIncident.id).all()
    ids = [item.id for item in records]
    client.post("/api/v1/abuse/incidents/discard", headers=admin, json={"ids": ids, "reason": "Engano"})
    url = "/api/v1/abuse/incidents/restore"
    payload = {"ids": ids, "reason": "Denúncias legítimas"}
    assert client.post(url, headers=operator, json=payload).status_code == 403
    assert client.post(url, headers=admin, json={"ids": [True], "reason": "Motivo"}).status_code == 400
    assert client.post(url, headers=admin, json={"ids": ids, "reason": " "}).status_code == 400
    assert client.post(url, headers=admin, json={"ids": ids + [99999], "reason": "Motivo"}).status_code == 404
    assert all(item.status == "discarded" for item in records)
    response = client.post(url, headers=admin, json=payload)
    assert response.get_json() == {"restored": 2}
    assert all(item.status == "review" and item.handled_at is None and item.handled_by_user_id is None for item in records)
    entries = AbuseAuditLog.query.filter_by(action="restore").all()
    assert len(entries) == 2
    assert json.loads(entries[0].details)["reason"] == "Denúncias legítimas"
    assert entries[0].user_id is not None
    assert client.post(url, headers=admin, json=payload).get_json() == {"restored": 0}
    assert AbuseIncident.query.count() == 2
    assert AbuseAuditLog.query.filter_by(action="restore").count() == 2
    assert client.get("/api/v1/abuse/incidents", headers=admin).get_json()["total"] == 2


def test_restore_refuses_anonymized_batch_atomically(client, admin):
    for index in range(2):
        add_message(csv_message(f"<anonrestore{index}@x.example>", ip=f"203.0.113.{index + 1}"))
    records = AbuseIncident.query.order_by(AbuseIncident.id).all()
    for item in records:
        item.status = "discarded"
    records[-1].anonymized_at = datetime.utcnow()
    db.session.commit()
    response = client.post("/api/v1/abuse/incidents/restore", headers=admin,
                           json={"ids": [item.id for item in records], "reason": "Engano"})
    assert response.status_code == 409
    assert all(item.status == "discarded" for item in records)
    assert AbuseAuditLog.query.filter_by(action="restore").count() == 0


def test_bulk_reprocess_requires_access(client, operator):
    assert client.post("/api/v1/abuse/messages/reprocess", headers=operator, json={}).status_code == 403
