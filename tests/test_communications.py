"""Envio de comunicados por e-mail: SMTP em Parâmetros, histórico e marca no ofício."""

import smtplib

import pytest

from app import mailer
from app.models import SentEmail, UploadBatch, db

SMTP = {
    "smtp_host": "smtp.exemplo.com.br",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_user": "noc@exemplo.com.br",
    "smtp_password": "smtp-secreta",
    "smtp_from_email": "noc@exemplo.com.br",
    "smtp_from_name": "NOC Exemplo",
    "email_signature": "Equipe NOC\n19 99999-0000",
}


def auth(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


@pytest.fixture
def headers(client):
    return auth(client)


@pytest.fixture
def office(app):
    with app.app_context():
        batch = UploadBatch(
            office_number="234", office_key="234", process_number="53500.099328/2024-86",
            filename="x", stored_filename="manual-x",
        )
        db.session.add(batch)
        db.session.commit()
        return batch.id


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(mailer, "send_email", lambda *args: calls.append(args))
    monkeypatch.setattr("app.api.communication_routes.send_email", lambda *args: calls.append(args))
    return calls


def save_smtp(client, headers):
    assert client.put("/api/v1/parameter-settings", headers=headers, json=SMTP).status_code == 200


def send(client, headers, **overrides):
    payload = {"recipients": "a@x.com.br; b@x.com.br", "subject": "Retorno", "body": "Prezados,", **overrides}
    return client.post("/api/v1/communications/send", headers=headers, json=payload)


def test_senha_smtp_nunca_sai_pela_api(client, headers):
    save_smtp(client, headers)
    body = client.get("/api/v1/parameter-settings", headers=headers).get_data(as_text=True)
    assert "smtp-secreta" not in body
    data = client.get("/api/v1/parameter-settings", headers=headers).get_json()
    assert data["smtp_password_set"] is True and data["email_signature"] == SMTP["email_signature"]

    # Senha vazia mantém a atual; clear apaga.
    client.put("/api/v1/parameter-settings", headers=headers, json={**SMTP, "smtp_password": ""})
    assert client.get("/api/v1/parameter-settings", headers=headers).get_json()["smtp_password_set"] is True
    client.put("/api/v1/parameter-settings", headers=headers, json={"clear_smtp_password": True})
    assert client.get("/api/v1/parameter-settings", headers=headers).get_json()["smtp_password_set"] is False


def test_parametros_smtp_invalidos(client, headers):
    assert client.put("/api/v1/parameter-settings", headers=headers, json={"smtp_port": "abc"}).status_code == 400
    assert client.put("/api/v1/parameter-settings", headers=headers, json={"smtp_security": "x"}).status_code == 400
    assert client.put("/api/v1/parameter-settings", headers=headers, json={"smtp_from_email": "sem-arroba"}).status_code == 400


def test_envio_sem_smtp_configurado(client, headers):
    response = send(client, headers)
    assert response.status_code == 400 and "SMTP" in response.get_json()["error"]


def test_envio_valida_campos(client, headers, sent):
    save_smtp(client, headers)
    assert send(client, headers, recipients="").status_code == 400
    assert send(client, headers, recipients="a@x.com.br, ruim").status_code == 400
    assert send(client, headers, subject="  ").status_code == 400
    assert send(client, headers, body="").status_code == 400
    assert send(client, headers, office_id=999).status_code == 404
    assert sent == []


def test_envio_registra_historico_e_marca_oficio(client, headers, sent, office):
    save_smtp(client, headers)
    response = send(client, headers, office_id=office, recipients=["a@x.com.br", "A@x.com.br", "b@x.com.br"])
    assert response.status_code == 201
    assert sent[0][1] == ["a@x.com.br", "b@x.com.br"]

    email = response.get_json()["email"]
    assert email["status"] == "sent" and email["office_number"] == "234" and email["username"] == "admin"
    assert email["body"].endswith("-- \nEquipe NOC\n19 99999-0000\n")

    listing = client.get("/api/v1/communications/emails", headers=headers).get_json()
    assert listing["total"] == 1 and listing["items"][0]["recipients"] == ["a@x.com.br", "b@x.com.br"]
    assert client.get(f"/api/v1/offices/{office}", headers=headers).get_json()["notification_sent_at"]


def test_falha_no_smtp_registra_e_nao_marca_oficio(client, headers, monkeypatch, office):
    save_smtp(client, headers)

    def boom(*args):
        raise smtplib.SMTPAuthenticationError(535, b"nope")

    monkeypatch.setattr("app.api.communication_routes.send_email", boom)
    response = send(client, headers, office_id=office)
    assert response.status_code == 502 and "senha" in response.get_json()["error"]

    items = client.get("/api/v1/communications/emails", headers=headers).get_json()["items"]
    assert items[0]["status"] == "failed"
    assert client.get(f"/api/v1/offices/{office}", headers=headers).get_json()["notification_sent_at"] is None


def test_marcar_e_desmarcar_notificacao(client, headers, office):
    url = f"/api/v1/offices/{office}/notification"
    assert client.put(url, headers=headers, json={"sent": True}).get_json()["notification_sent_at"]
    assert client.put(url, headers=headers, json={"sent": False}).get_json()["notification_sent_at"] is None
    assert client.put("/api/v1/offices/999/notification", headers=headers, json={}).status_code == 404


def test_remover_oficio_mantem_historico(client, headers, sent, office):
    save_smtp(client, headers)
    send(client, headers, office_id=office)
    assert client.delete(f"/api/v1/offices/{office}", headers=headers, json={"confirm_office_number": "234"}).status_code == 200
    item = client.get("/api/v1/communications/emails", headers=headers).get_json()["items"][0]
    assert item["office_id"] is None and item["office_number"] == "234"


def test_teste_de_conexao_smtp(client, headers, monkeypatch):
    assert client.post("/api/v1/parameter-settings/smtp-test", headers=headers, json={}).status_code == 400
    monkeypatch.setattr("app.api.routes.test_smtp_connection", lambda settings: None)
    assert client.post("/api/v1/parameter-settings/smtp-test", headers=headers, json=SMTP).status_code == 200

    def boom(settings):
        raise OSError("connection refused")

    monkeypatch.setattr("app.api.routes.test_smtp_connection", boom)
    assert client.post("/api/v1/parameter-settings/smtp-test", headers=headers, json=SMTP).status_code == 502
    # O teste não grava os dados do formulário.
    assert client.get("/api/v1/parameter-settings", headers=headers).get_json()["smtp_host"] == ""


def test_parse_recipients_lista_com_itens_compostos():
    assert mailer.parse_recipients(["a@x.com;b@y.com", "c@z.com"]) == (["a@x.com", "b@y.com", "c@z.com"], [])


def test_envio_multipart_separa_destinatarios(client, headers, sent, office):
    save_smtp(client, headers)
    response = send_multipart(client, headers, office, recipients="a@x.com.br;b@x.com.br")
    assert response.status_code == 201, response.get_json()
    assert sent[0][1] == ["a@x.com.br", "b@x.com.br"]


def test_parse_recipients():
    assert mailer.parse_recipients("a@x.com, b@y.com;c@z.com\nA@x.com") == (["a@x.com", "b@y.com", "c@z.com"], [])
    assert mailer.parse_recipients("a@x.com foo @bar") == (["a@x.com"], ["foo", "@bar"])


# --- caixa de abuse (IMAP) em Parâmetros -------------------------------------------------

IMAP = {
    "imap_host": "imap.exemplo.com.br",
    "imap_port": 993,
    "imap_user": "abuse@exemplo.com.br",
    "imap_password": "imap-secreta",
    "imap_mailbox": "INBOX",
}


def test_imap_salva_sem_devolver_senha(client, headers):
    assert client.put("/api/v1/parameter-settings", headers=headers, json=IMAP).status_code == 200
    response = client.get("/api/v1/parameter-settings", headers=headers)
    assert "imap-secreta" not in response.get_data(as_text=True)
    data = response.get_json()
    assert data["imap_password_set"] is True and data["imap_host"] == IMAP["imap_host"]

    client.put("/api/v1/parameter-settings", headers=headers, json={**IMAP, "imap_password": ""})
    assert client.get("/api/v1/parameter-settings", headers=headers).get_json()["imap_password_set"] is True
    client.put("/api/v1/parameter-settings", headers=headers, json={"clear_imap_password": True})
    assert client.get("/api/v1/parameter-settings", headers=headers).get_json()["imap_password_set"] is False
    assert client.put("/api/v1/parameter-settings", headers=headers, json={"imap_port": "x"}).status_code == 400


def test_imap_importa_env_uma_vez(app, monkeypatch):
    from app import import_legacy_imap_settings
    from app.models import ParameterSettings

    monkeypatch.setenv("ABUSE_IMAP_HOST", "imap.legado.example")
    monkeypatch.setenv("ABUSE_IMAP_USER", "abuse@legado.example")
    monkeypatch.setenv("ABUSE_IMAP_PASSWORD", "legado")
    with app.app_context():
        import_legacy_imap_settings()
        settings = ParameterSettings.query.first()
        assert (settings.imap_host, settings.imap_port, settings.imap_password) == ("imap.legado.example", 993, "legado")

        settings.imap_host = "imap.novo.example"
        db.session.commit()
        import_legacy_imap_settings()
        assert ParameterSettings.query.first().imap_host == "imap.novo.example"


def test_teste_de_conexao_imap(client, headers, monkeypatch):
    assert client.post("/api/v1/parameter-settings/imap-test", headers=headers, json={}).status_code == 400

    class FakeConnection:
        logged_out = False

        def logout(self):
            FakeConnection.logged_out = True

    monkeypatch.setattr("app.api.routes.imap_connect", lambda config: FakeConnection())
    monkeypatch.setattr("app.api.routes.ReadOnlyMailbox", lambda connection, mailbox: None)
    assert client.post("/api/v1/parameter-settings/imap-test", headers=headers, json=IMAP).status_code == 200
    assert FakeConnection.logged_out

    def boom(config):
        raise OSError("connection refused")

    monkeypatch.setattr("app.api.routes.imap_connect", boom)
    assert client.post("/api/v1/parameter-settings/imap-test", headers=headers, json=IMAP).status_code == 502
    assert client.get("/api/v1/parameter-settings", headers=headers).get_json()["imap_host"] == ""


# --- anexos ---------------------------------------------------------------------------

def office_with_items(app, office):
    from app.models import Domain, IpAddress, IpBatch, IpBatchAddress, OfficeDomain

    with app.app_context():
        domain = Domain(name="bloqueado.example")
        ip = IpAddress(address="203.0.113.7", version=4)
        batch = IpBatch(office_id=office, name="234", office_key="234", filename="x")
        db.session.add_all([domain, ip, batch])
        db.session.flush()
        db.session.add_all(
            [OfficeDomain(office_id=office, domain_id=domain.id), IpBatchAddress(batch_id=batch.id, ip_id=ip.id)]
        )
        db.session.commit()


def send_multipart(client, headers, office, **extra):
    import io

    data = {
        "recipients": "a@x.com.br",
        "subject": "Retorno",
        "body": "Prezados,",
        "office_id": str(office),
        **{k: v for k, v in extra.items() if k != "files"},
    }
    data["attachments"] = [(io.BytesIO(content), name) for name, content in extra.get("files", [])]
    return client.post("/api/v1/communications/send", headers=headers, data=data, content_type="multipart/form-data")


def test_anexa_zona_ips_e_arquivos_do_computador(app, client, headers, sent, office):
    save_smtp(client, headers)
    office_with_items(app, office)
    response = send_multipart(
        client, headers, office, attach_zone="true", attach_ips="true", files=[("oficio.pdf", b"%PDF-1.4 x")]
    )
    assert response.status_code == 201, response.get_json()

    attachments = dict(sent[0][4])
    assert set(attachments) == {"oficio-234-db.rpz.zone", "oficio-234-config.txt", "oficio.pdf"}
    assert b"bloqueado.example CNAME ." in attachments["oficio-234-db.rpz.zone"]
    assert b"203.0.113.7" in attachments["oficio-234-config.txt"]
    assert response.get_json()["email"]["attachments"] == list(attachments)


def test_anexos_validam(client, headers, sent, office):
    save_smtp(client, headers)
    # Ofício sem domínios/IPs ativos.
    assert send_multipart(client, headers, office, attach_zone="true").status_code == 400
    assert send_multipart(client, headers, office, attach_ips="true").status_code == 400
    # Sem ofício selecionado não há o que gerar.
    response = client.post(
        "/api/v1/communications/send", headers=headers,
        json={"recipients": "a@x.com.br", "subject": "s", "body": "b", "attach_zone": True},
    )
    assert response.status_code == 400
    too_many = [(f"f{i}.txt", b"x") for i in range(11)]
    assert send_multipart(client, headers, office, files=too_many).status_code == 400
    assert sent == []


def test_mailer_monta_mensagem_com_anexos(monkeypatch):
    from app.models import ParameterSettings

    captured = []

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def send_message(self, message):
            captured.append(message)

    monkeypatch.setattr(mailer, "connect", lambda settings: FakeClient())
    settings = ParameterSettings(smtp_host="h", smtp_from_email="noc@x.com.br")
    mailer.send_email(
        settings, ["a@x.com.br"], "Assunto", "Texto",
        [("db.rpz.zone", b"zona"), ("a.pdf", b"%PDF"), ("sem-tipo.xyz123", b"1")],
    )
    parts = {part.get_filename(): part.get_content_type() for part in captured[0].iter_attachments()}
    assert parts == {"db.rpz.zone": "text/plain", "a.pdf": "application/pdf", "sem-tipo.xyz123": "application/octet-stream"}
