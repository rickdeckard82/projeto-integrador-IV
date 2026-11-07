"""Backup agendado por FTP: agenda, envio, retenção e API. Sem rede: FTP falso."""

import ftplib
import io
import zipfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from app import backup_ftp
from app.backup_ftp import execute, get_backup_schedule, is_due, next_run_utc, prune, run_backup
from app.models import BackupSchedule, Deployment, db

SP = ZoneInfo("America/Sao_Paulo")


class FakeFtp:
    """Guarda os arquivos em memória; imita o suficiente do ftplib para o módulo."""

    def __init__(self, files=None, fail_login=False):
        self.files = dict(files or {})
        self.dirs = ["/"]
        self.cwd_path = "/"
        self.fail_login = fail_login
        self.closed = False

    # conexão
    def connect(self, host, port):
        self.address = (host, port)

    def login(self, user, password):
        if self.fail_login:
            raise ftplib.error_perm("530 Login incorrect.")
        self.credentials = (user, password)

    def prot_p(self):
        self.protected = True

    def set_pasv(self, value):
        pass

    def quit(self):
        self.closed = True

    def close(self):
        self.closed = True

    # pastas
    def cwd(self, segment):
        target = "/" if segment == "/" else f"{self.cwd_path.rstrip('/')}/{segment}"
        if target not in self.dirs:
            raise ftplib.error_perm("550 No such directory")
        self.cwd_path = target

    def mkd(self, segment):
        self.dirs.append(f"{self.cwd_path.rstrip('/')}/{segment}")

    # arquivos (só na pasta atual)
    def storbinary(self, command, handle):
        self.files[command.split(" ", 1)[1]] = handle.read()

    def voidcmd(self, command):
        return "200"

    def size(self, name):
        return len(self.files[name])

    def delete(self, name):
        if name not in self.files:
            raise ftplib.error_perm("550 Not found")
        del self.files[name]

    def rename(self, source, target):
        self.files[target] = self.files.pop(source)

    def nlst(self):
        return sorted(self.files)


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield app


@pytest.fixture
def schedule(ctx):
    schedule = get_backup_schedule()
    schedule.enabled = True
    schedule.run_time = "02:30"
    schedule.ftp_host = "ftp.example"
    schedule.ftp_user = "backup"
    schedule.ftp_password = "segredo"
    schedule.ftp_directory = "oficios/prod"
    schedule.keep_count = 2
    db.session.commit()
    return schedule


@pytest.fixture
def fake_ftp(monkeypatch):
    server = FakeFtp()
    monkeypatch.setattr(backup_ftp.ftplib, "FTP_TLS", lambda timeout: server)
    monkeypatch.setattr(backup_ftp.ftplib, "FTP", lambda timeout: server)
    # Sem MySQL nos testes: o dump é simulado.
    monkeypatch.setattr(backup_ftp, "write_database_backup", lambda path: path.write_bytes(b"dump"))
    return server


def utc(year, month, day, hour, minute):
    """Horário local de São Paulo -> UTC naive."""
    return datetime(year, month, day, hour, minute, tzinfo=SP).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)


# --- agenda -------------------------------------------------------------------------

def test_due_only_after_scheduled_time_and_once_per_day(schedule):
    assert not is_due(schedule, utc(2026, 10, 20, 2, 29))
    assert is_due(schedule, utc(2026, 10, 20, 2, 30))
    schedule.last_attempt_at = utc(2026, 10, 20, 2, 30)
    assert not is_due(schedule, utc(2026, 10, 20, 3, 0))
    assert is_due(schedule, utc(2026, 10, 21, 2, 31))


def test_not_due_long_after_scheduled_time(schedule):
    # Ligar o agendamento às 15h não dispara o backup das 02:30 na hora.
    assert not is_due(schedule, utc(2026, 10, 20, 15, 0))
    assert next_run_utc(schedule, utc(2026, 10, 20, 15, 0)) == utc(2026, 10, 21, 2, 30)


def test_disabled_runs_only_when_requested(schedule):
    schedule.enabled = False
    assert not is_due(schedule, utc(2026, 10, 20, 2, 30))
    assert next_run_utc(schedule, utc(2026, 10, 20, 2, 0)) is None
    schedule.run_requested_at = datetime(2026, 10, 20, 12, 0)
    assert is_due(schedule, utc(2026, 10, 20, 15, 0))


# --- envio e retenção ---------------------------------------------------------------

def test_run_backup_uploads_database_and_files_into_created_directory(app, schedule, fake_ftp):
    office_dir = Path(app.config["UPLOAD_FOLDER"], "office")
    office_dir.mkdir(parents=True)
    (office_dir / "intimacao.pdf").write_bytes(b"%PDF")
    result = run_backup(schedule, now=datetime(2026, 10, 20, 2, 30, 0))
    assert fake_ftp.cwd_path == "/oficios/prod"
    assert fake_ftp.protected is True
    assert fake_ftp.credentials == ("backup", "segredo")
    assert sorted(fake_ftp.files) == [
        "oficios-rpz-arquivos-20261020-023000.zip",
        "oficios-rpz-banco-20261020-023000.sql.gz",
    ]
    assert fake_ftp.files["oficios-rpz-banco-20261020-023000.sql.gz"] == b"dump"
    archive = zipfile.ZipFile(io.BytesIO(fake_ftp.files["oficios-rpz-arquivos-20261020-023000.zip"]))
    assert archive.namelist() == ["office/intimacao.pdf"]
    assert result.file_count == 1
    assert fake_ftp.closed


class WriteOnlyFtp(FakeFtp):
    """Como o Pulse Backup: só STOR; SIZE, DELE, renomear e listar são recusados."""

    def size(self, name):
        raise ftplib.error_perm("550 not retrievable.")

    def delete(self, name):
        raise ftplib.error_perm("550 Not enough privileges.")

    def rename(self, source, target):
        raise ftplib.error_perm("550 No such file or directory.")

    def nlst(self):
        raise AssertionError("não deve listar um destino só de gravação")


def test_write_only_destination_uploads_final_names_and_never_prunes(schedule, monkeypatch):
    server = WriteOnlyFtp({"oficios-rpz-banco-20261001-023000.sql.gz": b"antigo"})
    monkeypatch.setattr(backup_ftp.ftplib, "FTP_TLS", lambda timeout: server)
    monkeypatch.setattr(backup_ftp.ftplib, "FTP", lambda timeout: server)
    monkeypatch.setattr(backup_ftp, "write_database_backup", lambda path: path.write_bytes(b"dump"))
    schedule.ftp_write_only = True
    db.session.commit()
    result = run_backup(schedule, now=datetime(2026, 10, 20, 2, 30, 0))
    assert sorted(server.files) == [
        "oficios-rpz-arquivos-20261020-023000.zip",
        "oficios-rpz-banco-20261001-023000.sql.gz",  # nada apagado: retenção é do destino
        "oficios-rpz-banco-20261020-023000.sql.gz",
    ]
    assert not any(name.endswith(".part") for name in server.files)
    assert result.removed == []


def test_api_write_only_flag_round_trip(client, ctx, fake_ftp):
    headers = login(client)
    body = client.put("/api/v1/backup/schedule", json={"ftp_write_only": True}, headers=headers).get_json()
    assert body["ftp_write_only"] is True
    response = client.post(
        "/api/v1/backup/schedule/test", json={"ftp_host": "ftp.example", "ftp_write_only": True}, headers=headers
    )
    assert "só de gravação" in response.get_json()["message"]


@pytest.fixture
def temp_dir(tmp_path, monkeypatch):
    path = tmp_path / "tmp"
    path.mkdir()
    monkeypatch.setattr(backup_ftp.tempfile, "tempdir", str(path))
    return path


def test_no_local_copy_left_after_upload(schedule, fake_ftp, temp_dir):
    uploaded_while_present = []
    original_rename = fake_ftp.rename

    def rename(source, target):
        original_rename(source, target)
        uploaded_while_present.append(list(temp_dir.rglob("*.zip")) + list(temp_dir.rglob("*.sql.gz")))

    fake_ftp.rename = rename
    run_backup(schedule)
    assert len(fake_ftp.files) == 2
    # Banco apagado assim que enviado, antes do envio do .zip terminar.
    assert [path.name.endswith(".zip") for path in uploaded_while_present[1]] == [True]
    assert list(temp_dir.iterdir()) == []


def test_no_local_copy_left_after_failure(schedule, fake_ftp, temp_dir):
    fake_ftp.fail_login = True
    with pytest.raises(ftplib.error_perm):
        run_backup(schedule)
    assert list(temp_dir.iterdir()) == []


def test_clean_leftovers_removes_only_backup_temp_dirs(tmp_path):
    (tmp_path / "oficios-backup-abc").mkdir()
    (tmp_path / "oficios-backup-abc" / "oficios-rpz-banco-20261020-023000.sql.gz").write_bytes(b"x")
    (tmp_path / "outra-coisa").mkdir()
    assert backup_ftp.clean_leftovers(tmp_path) == 1
    assert [path.name for path in tmp_path.iterdir()] == ["outra-coisa"]


def test_prune_keeps_newest_per_kind_and_ignores_other_files():
    names = [f"oficios-rpz-banco-2026102{d}-023000.sql.gz" for d in range(4)]
    names += [f"oficios-rpz-arquivos-2026102{d}-023000.zip" for d in range(4)]
    names += ["outro-sistema.sql.gz", "oficios-rpz-banco-20261023-023000.sql.gz.part"]
    server = FakeFtp({name: b"x" for name in names})
    removed = prune(server, 2)
    assert sorted(removed) == [
        "oficios-rpz-arquivos-20261020-023000.zip",
        "oficios-rpz-arquivos-20261021-023000.zip",
        "oficios-rpz-banco-20261020-023000.sql.gz",
        "oficios-rpz-banco-20261021-023000.sql.gz",
    ]
    assert "outro-sistema.sql.gz" in server.files
    assert "oficios-rpz-banco-20261023-023000.sql.gz.part" in server.files


def test_execute_records_success_in_schedule_and_log(schedule, fake_ftp):
    schedule.run_requested_at = datetime.utcnow()
    schedule.include_files = False
    db.session.commit()
    assert execute() is True
    schedule = BackupSchedule.query.one()
    assert schedule.last_status == "success"
    assert schedule.run_requested_at is None
    assert schedule.last_success_at is not None
    assert "oficios-rpz-banco-" in schedule.last_message
    [deployment] = Deployment.query.filter_by(deployment_type="backup-ftp").all()
    assert deployment.status == "success"
    assert execute() is False  # pedido atendido e fora do horário


def test_execute_records_login_failure(schedule, fake_ftp):
    fake_ftp.fail_login = True
    schedule.run_requested_at = datetime.utcnow()
    db.session.commit()
    execute()
    schedule = BackupSchedule.query.one()
    assert schedule.last_status == "error"
    assert schedule.last_message.startswith("Login FTP recusado")
    assert Deployment.query.filter_by(deployment_type="backup-ftp").one().status == "error"


# --- API ----------------------------------------------------------------------------

def login(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def test_api_never_returns_password_and_keeps_it_when_blank(client, ctx):
    headers = login(client)
    payload = {
        "enabled": True, "run_time": "03:15", "keep_count": 5, "ftp_host": "ftp.example",
        "ftp_port": 2121, "ftp_user": "backup", "ftp_password": "segredo", "ftp_directory": "/bk",
    }
    response = client.put("/api/v1/backup/schedule", json=payload, headers=headers)
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert "ftp_password" not in body
    assert body["ftp_password_set"] is True
    assert body["next_run_at"]
    response = client.put("/api/v1/backup/schedule", json={**payload, "ftp_password": ""}, headers=headers)
    assert BackupSchedule.query.one().ftp_password == "segredo"


@pytest.mark.parametrize("payload,message", [
    ({"run_time": "25:00"}, "Horário inválido"),
    ({"keep_count": 0}, "Cópias mantidas"),
    ({"ftp_port": 70000}, "Porta FTP"),
    ({"enabled": True, "ftp_host": ""}, "Servidor FTP"),
    ({"enabled": True, "ftp_host": "ftp.example", "include_database": False, "include_files": False}, "Nada selecionado"),
])
def test_api_validates_schedule(client, ctx, payload, message):
    response = client.put("/api/v1/backup/schedule", json=payload, headers=login(client))
    assert response.status_code == 400
    assert message in response.get_json()["error"]


def test_api_run_now_requires_config_and_sets_request(client, ctx):
    headers = login(client)
    assert client.post("/api/v1/backup/schedule/run", headers=headers).status_code == 400
    client.put("/api/v1/backup/schedule", json={"ftp_host": "ftp.example"}, headers=headers)
    response = client.post("/api/v1/backup/schedule/run", headers=headers)
    assert response.status_code == 202
    assert BackupSchedule.query.one().run_requested_at is not None


def test_api_test_connection_does_not_save(client, ctx, fake_ftp):
    headers = login(client)
    fake_ftp.files["oficios-rpz-banco-20261020-023000.sql.gz"] = b"x"
    response = client.post(
        "/api/v1/backup/schedule/test", json={"ftp_host": "ftp.example", "ftp_password": "x"}, headers=headers
    )
    assert response.status_code == 200, response.get_json()
    assert "1 backup" in response.get_json()["message"]
    assert BackupSchedule.query.one().ftp_host is None
    fake_ftp.fail_login = True
    response = client.post("/api/v1/backup/schedule/test", json={"ftp_host": "ftp.example"}, headers=headers)
    assert response.status_code == 502
    assert "Login FTP recusado" in response.get_json()["error"]
