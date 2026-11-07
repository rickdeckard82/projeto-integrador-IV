"""Servidores BIND, roteadores e servidor de nomes cadastrados em Geral > Parâmetros."""

import json

import pytest

from app import import_legacy_ssh_settings
from app import ssh_publish
from app.models import ParameterSettings, db
from app.services import configured_bind_servers, configured_router_targets

BIND = {
    "name": "dns-a",
    "host": "192.0.2.53",
    "port": 2222,
    "user": "deploy",
    "password": "bind-secreta",
    "sudo_password": "sudo-secreta",
}
ROUTER = {"name": "borda", "host": "192.0.2.1", "user": "netops", "key_path": "/run/secrets/router_key"}


def auth(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def put(client, headers, **payload):
    return client.put("/api/v1/parameter-settings", headers=headers, json=payload)


def test_senhas_nunca_saem_pela_api(client):
    headers = auth(client)
    response = put(client, headers, rpz_servers=[BIND], publish_routers=[ROUTER])
    assert response.status_code == 200

    body = client.get("/api/v1/parameter-settings", headers=headers).get_data(as_text=True)
    assert "bind-secreta" not in body and "sudo-secreta" not in body
    data = json.loads(body)
    server = data["rpz_servers"][0]
    assert server["password_set"] and server["sudo_password_set"] and not server["key_passphrase_set"]
    assert server["port"] == 2222
    assert server["remote_path"] == "/var/cache/bind/db.rpz.zone"
    assert data["publish_routers"][0]["key_path"] == "/run/secrets/router_key"


def test_senha_em_branco_mantem_e_clear_apaga(app, client):
    headers = auth(client)
    saved = put(client, headers, rpz_servers=[BIND]).get_json()["rpz_servers"][0]

    resend = {**saved, "password": "", "sudo_password": "", "user": "outro"}
    assert put(client, headers, rpz_servers=[resend]).status_code == 200
    with app.app_context():
        server = configured_bind_servers()[0]
        assert (server["user"], server["password"], server["sudo_password"]) == (
            "outro", "bind-secreta", "sudo-secreta"
        )

    put(client, headers, rpz_servers=[{**resend, "clear": ["sudo_password"]}])
    with app.app_context():
        server = configured_bind_servers()[0]
        assert server["password"] == "bind-secreta" and server["sudo_password"] == ""


def test_varios_servidores_e_roteadores(app, client):
    headers = auth(client)
    second = {**BIND, "name": "dns-b", "host": "192.0.2.54"}
    other_router = {**ROUTER, "name": "borda-2", "host": "192.0.2.2"}
    put(client, headers, rpz_servers=[BIND, second], publish_routers=[ROUTER, other_router])
    with app.app_context():
        assert [s["host"] for s in configured_bind_servers()] == ["192.0.2.53", "192.0.2.54"]
        assert [r["name"] for r in configured_router_targets()] == ["borda", "borda-2"]


@pytest.mark.parametrize(
    "item, message",
    [
        ({"name": "x", "user": "u", "password": "p"}, "IP/host"),
        ({"host": "192.0.2.9", "password": "p"}, "usuário SSH"),
        ({"host": "192.0.2.9", "user": "u"}, "senha ou o caminho da chave"),
        ({"host": "192.0.2.9", "user": "u", "password": "p", "port": 70000}, "Porta SSH"),
    ],
)
def test_validacao(client, item, message):
    response = put(client, auth(client), publish_routers=[item])
    assert response.status_code == 400
    assert message in response.get_json()["error"]


def test_linha_em_branco_e_ignorada(client):
    response = put(client, auth(client), publish_routers=[{"name": "", "host": "", "user": ""}])
    assert response.status_code == 200
    assert response.get_json()["publish_routers"] == []


def test_servidor_de_nomes_na_zona(client):
    headers = auth(client)
    assert "SOA localhost. localhost." in client.get("/api/v1/rpz", headers=headers).get_json()["zone"]

    assert put(client, headers, rpz_nameserver="ns1.exemplo.com.br.").status_code == 200
    zone = client.get("/api/v1/rpz", headers=headers).get_json()["zone"]
    assert "SOA localhost. ns1.exemplo.com.br. (" in zone
    assert "NS      ns1.exemplo.com.br." in zone

    assert put(client, headers, rpz_nameserver="não é nome").status_code == 400


def test_importa_config_antiga_do_env_uma_vez(app, monkeypatch):
    monkeypatch.setenv("SSH_HOST", "192.0.2.53")
    monkeypatch.setenv("SSH_USER", "deploy")
    monkeypatch.setenv("SSH_KEY_PATH", "/run/secrets/bind_ssh_key")
    monkeypatch.setenv("SUDO_PASSWORD", "sudo-secreta")
    monkeypatch.setenv("ROUTER_SSH_USER", "netops")
    monkeypatch.setenv("ROUTER_SSH_PASSWORD", "router-secreta")
    monkeypatch.setenv("SSH_STRICT_HOST_KEY_CHECKING", "true")
    monkeypatch.setenv("RPZ_NAMESERVER", "ns1.exemplo.com.br")

    with app.app_context():
        settings = ParameterSettings(publish_routers=json.dumps([{"name": "borda", "host": "192.0.2.1"}]))
        db.session.add(settings)
        db.session.commit()

        import_legacy_ssh_settings()
        server = configured_bind_servers()[0]
        assert (server["host"], server["user"], server["sudo_password"]) == ("192.0.2.53", "deploy", "sudo-secreta")
        router = configured_router_targets()[0]
        assert (router["name"], router["user"], router["password"]) == ("borda", "netops", "router-secreta")
        assert settings.rpz_nameserver == "ns1.exemplo.com.br"
        assert settings.ssh_strict_host_key_checking is True

        # Depois de importado (ou salvo pela tela), o .env não é mais lido.
        settings.rpz_servers = json.dumps([])
        db.session.commit()
        import_legacy_ssh_settings()
        assert configured_bind_servers() == []


def test_sem_env_nao_importa(app):
    with app.app_context():
        import_legacy_ssh_settings()
        assert ParameterSettings.query.count() == 0


def test_publish_zone_publica_em_todos_e_relata_falhas(monkeypatch):
    calls = []

    def fake(zone_text, server, strict):
        calls.append((server["host"], strict))
        if server["host"] == "192.0.2.54":
            raise RuntimeError("sem rota")
        return "ok"

    monkeypatch.setattr(ssh_publish, "publish_zone_to_server", fake)
    servers = [{"name": "a", "host": "192.0.2.53"}, {"name": "b", "host": "192.0.2.54"}]
    with pytest.raises(RuntimeError) as error:
        ssh_publish.publish_zone("zona", servers, strict_host_key_checking=False)
    assert calls == [("192.0.2.53", False), ("192.0.2.54", False)]
    assert "a (192.0.2.53):\nok" in str(error.value) and "b (192.0.2.54): sem rota" in str(error.value)


def test_publicar_sem_cadastro_avisa():
    with pytest.raises(RuntimeError, match="servidor BIND em Geral > Parâmetros"):
        ssh_publish.publish_zone("zona", [])
    with pytest.raises(RuntimeError, match="roteador em Geral > Parâmetros"):
        ssh_publish.publish_ip_routes("set x", [])


def test_sudo_com_senha_usa_sudo_s():
    command = ssh_publish.build_publish_command("/tmp/z", "/var/z", "/var/z.bak", "rndc reload", use_sudo_password=True)
    assert command.startswith("sudo -S -p ''")
    command = ssh_publish.build_publish_command("/tmp/z", "/var/z", "/var/z.bak", "rndc reload")
    assert command.startswith("sudo -n")
