import shlex
import time
from datetime import datetime
from pathlib import Path

import paramiko


def publish_zone(zone_text, servers, strict_host_key_checking=True):
    """Publica a zona em cada servidor BIND cadastrado em Parâmetros."""
    if not servers:
        raise RuntimeError("Cadastre ao menos um servidor BIND em Geral > Parâmetros antes de publicar.")

    results = []
    errors = []
    for server in servers:
        label = f"{server['name']} ({server['host']})"
        try:
            output = publish_zone_to_server(zone_text, server, strict_host_key_checking)
            results.append(f"{label}:\n{output}")
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    summary = "\n\n".join(results + errors)
    if errors:
        raise RuntimeError(summary)
    return summary


def publish_zone_to_server(zone_text, server, strict_host_key_checking):
    remote_path = server["remote_path"]
    tmp_path = f"/tmp/{Path(remote_path).name}.upload"
    backup_path = f"{remote_path}.{datetime.now().strftime('%Y%m%d%H%M')}"
    sudo_password = server.get("sudo_password") or None

    client = build_ssh_client(strict_host_key_checking)
    client.connect(**connect_kwargs_for(server))
    try:
        with client.open_sftp() as sftp:
            with sftp.file(tmp_path, "w") as remote_file:
                remote_file.write(zone_text)

        test_domain = first_blocked_domain(zone_text)
        redirect_domain, redirect_target = first_redirect_domain(zone_text)
        command = build_publish_command(
            tmp_path,
            remote_path,
            backup_path,
            server["reload_command"],
            test_domain,
            server["test_resolver"],
            redirect_domain,
            redirect_target,
            use_sudo_password=bool(sudo_password),
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        if sudo_password:
            stdin.write(f"{sudo_password}\n")
            stdin.flush()
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")

        if exit_status != 0:
            raise RuntimeError(error or output or f"Comando remoto falhou com status {exit_status}.")

        return output.strip() or f"Zona RPZ publicada. Backup criado em {backup_path}."
    finally:
        client.close()


def publish_ip_routes(route_config, routers, strict_host_key_checking=True):
    """Publica as rotas em cada roteador cadastrado em Parâmetros (cada um com suas credenciais)."""
    commands = [line.strip() for line in route_config.splitlines() if line.strip()]
    if not commands:
        raise RuntimeError("Nenhuma rota ativa para publicar.")
    if not routers:
        raise RuntimeError("Cadastre ao menos um roteador em Geral > Parâmetros antes de publicar.")

    results = []
    errors = []
    for router in routers:
        label = f"{router['name']} ({router['host']})"
        try:
            publish_commands_to_host(commands, router, strict_host_key_checking)
            results.append(f"{label}: {len(commands)} rotas discard publicadas.")
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    summary = "\n".join(results + errors)
    if errors:
        raise RuntimeError(summary)
    return summary


def publish_commands_to_host(commands, router, strict_host_key_checking):
    client = build_ssh_client(strict_host_key_checking)
    client.connect(**connect_kwargs_for(router))
    try:
        shell = client.invoke_shell()
        output = read_shell(shell)
        output += send_shell_command(shell, "set cli screen-length 0", timeout=8)
        output += send_shell_command(shell, "set cli screen-width 0", timeout=8)
        output += send_shell_command(shell, "configure exclusive")
        output += send_route_commands_in_batches(shell, commands)
        output += send_shell_command(
            shell,
            "commit check",
            timeout=commit_timeout(commands),
            quiet_seconds=1,
            expected_text="configuration check succeeds",
        )
        if "configuration check succeeds" not in output.lower():
            output += rollback_and_exit(shell)
            raise RuntimeError("commit check falhou ou não confirmou sucesso:\n" + tail(output))

        output += send_shell_command(
            shell,
            "commit",
            timeout=commit_timeout(commands, factor=2),
            quiet_seconds=1,
            expected_text="commit complete",
        )
        if "commit complete" not in output.lower():
            output += rollback_and_exit(shell)
            raise RuntimeError("commit falhou ou não confirmou sucesso:\n" + tail(output))

        output += send_shell_command(shell, "exit")
    finally:
        client.close()


def build_ssh_client(strict_host_key_checking):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if strict_host_key_checking:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client


def connect_kwargs_for(target):
    return build_connect_kwargs(
        host=target["host"],
        port=target["port"],
        user=target["user"],
        password=target.get("password") or None,
        key_path=target.get("key_path") or None,
        key_passphrase=target.get("key_passphrase") or None,
    )


def build_connect_kwargs(host, port, user, password=None, key_path=None, key_passphrase=None):
    connect_kwargs = {"hostname": host, "port": port, "username": user, "timeout": 15}
    if key_path:
        if not Path(key_path).is_file():
            raise RuntimeError(f"Chave SSH não encontrada no container: {key_path}")
        if Path(key_path).stat().st_size == 0:
            raise RuntimeError(f"Chave SSH está vazia no container: {key_path}")
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
        if key_passphrase:
            connect_kwargs["passphrase"] = key_passphrase
    elif password:
        connect_kwargs["password"] = password
    return connect_kwargs


def send_shell_command(shell, command, timeout=10, quiet_seconds=0.5, expected_text=None):
    shell.send(command + "\n")
    return read_shell(
        shell,
        timeout=timeout,
        quiet_seconds=quiet_seconds,
        expected_text=expected_text,
    )


def send_shell_commands(shell, commands, timeout=30, quiet_seconds=1):
    shell.send("\n".join(commands) + "\n")
    return read_shell(shell, timeout=timeout, quiet_seconds=quiet_seconds)


ROUTE_BATCH_SIZE = 200


def send_route_commands_in_batches(shell, commands, batch_size=ROUTE_BATCH_SIZE):
    # Envia em lotes menores para não seguir para o próximo comando antes do roteador
    # terminar de ecoar um lote grande, o que corrompe a linha (ex.: "routing-opcommit").
    output = ""
    for start in range(0, len(commands), batch_size):
        batch = commands[start : start + batch_size]
        output += send_shell_commands(shell, batch, timeout=20, quiet_seconds=1)
    return output


def commit_timeout(commands, factor=1):
    return max(30, (10 + len(commands) // 20) * factor)


def rollback_and_exit(shell):
    output = send_shell_command(shell, "rollback", timeout=15)
    output += send_shell_command(shell, "exit", timeout=10)
    return output


def read_shell(shell, timeout=5, quiet_seconds=0.5, expected_text=None):
    chunks = []
    deadline = time.time() + timeout
    last_data_at = time.time()
    expected_text = expected_text.lower() if expected_text else None

    while time.time() < deadline:
        if shell.recv_ready():
            chunks.append(shell.recv(65535).decode("utf-8", errors="replace"))
            last_data_at = time.time()
            output = clean_terminal_output("".join(chunks)).lower()
            if expected_text and expected_text in output:
                break
            continue
        if chunks and not expected_text and time.time() - last_data_at >= quiet_seconds:
            break
        time.sleep(0.1)

    return clean_terminal_output("".join(chunks))


def clean_terminal_output(value):
    while "\b" in value:
        value = re_backspace(value)
    return value


def re_backspace(value):
    result = []
    for char in value:
        if char == "\b":
            if result:
                result.pop()
        else:
            result.append(char)
    return "".join(result)


def tail(value, max_chars=3000):
    return value[-max_chars:]


def build_publish_command(
    tmp_path,
    remote_path,
    backup_path,
    reload_command,
    test_domain=None,
    test_resolver="127.0.0.1",
    redirect_domain=None,
    redirect_target=None,
    use_sudo_password=False,
):
    quoted_tmp = shlex.quote(tmp_path)
    quoted_remote = shlex.quote(remote_path)
    quoted_backup = shlex.quote(backup_path)
    reload_without_sudo = remove_sudo_prefix(reload_command)
    steps = [
        "set -eu",
        f"if [ -f {quoted_remote} ]; then cp -p {quoted_remote} {quoted_backup}; fi",
        f"install -m 0644 {quoted_tmp} {quoted_remote}",
        f"chown bind:bind {quoted_remote}",
        f"chmod 644 {quoted_remote}",
        f"{reload_without_sudo} >/dev/null",
        f"echo 'Backup criado: {backup_path}'",
        "echo 'Zona RPZ recarregada no BIND.'",
        "service bind9 status >/dev/null",
        "echo 'Status do BIND: ativo.'",
    ]
    if test_domain:
        steps.extend(build_dns_test_steps(test_domain, test_resolver))
    else:
        steps.append("echo 'Teste de bloqueio ignorado: nenhum domínio bloqueado ativo na zona.'")

    if redirect_domain:
        steps.extend(build_redirect_test_steps(redirect_domain, redirect_target, test_resolver))
    else:
        steps.append(
            "echo 'Teste de redirecionamento ignorado: nenhum domínio redirecionado ativo na zona.'"
        )

    script = " && ".join(steps)
    if use_sudo_password:
        return f"sudo -S -p '' sh -c {shlex.quote(script)}"
    return f"sudo -n sh -c {shlex.quote(script)}"


def build_dns_test_steps(test_domain, test_resolver):
    quoted_domain = shlex.quote(test_domain)
    quoted_resolver = shlex.quote(test_resolver)
    inner = "; ".join(
        [
            "if ! command -v dig >/dev/null 2>&1; then echo 'Teste de bloqueio ignorado: dig não encontrado no servidor.'; exit 0; fi",
            f"dig_status=$(dig +time=3 +tries=1 +noall +comments @{quoted_resolver} {quoted_domain} A | awk '/status:/ {{print $6}}' | tr -d ',')",
            "if [ \"$dig_status\" != 'NXDOMAIN' ]; then echo 'Aviso: bloqueio não confirmado pelo teste DNS.'; exit 0; fi",
            f"echo 'Bloqueio confirmado: {test_domain} respondeu NXDOMAIN.'",
        ]
    )
    return [f"( {inner} )"]


def build_redirect_test_steps(domain, target, test_resolver):
    quoted_domain = shlex.quote(domain)
    quoted_target = shlex.quote(target)
    quoted_resolver = shlex.quote(test_resolver)
    inner = "; ".join(
        [
            "if ! command -v dig >/dev/null 2>&1; then echo 'Teste de redirecionamento ignorado: dig não encontrado no servidor.'; exit 0; fi",
            f"redirect_answer=$(dig +time=3 +tries=1 +noall +answer @{quoted_resolver} {quoted_domain} A)",
            f"if ! echo \"$redirect_answer\" | grep -qiF {quoted_target}; then echo 'Aviso: redirecionamento não confirmado pelo teste DNS.'; exit 0; fi",
            f"echo 'Redirecionamento confirmado: {domain} aponta para {target}.'",
        ]
    )
    return [f"( {inner} )"]


def remove_sudo_prefix(command):
    command = command.strip()
    if command == "sudo":
        return ""
    if command.startswith("sudo "):
        return command[5:].strip()
    return command


def first_blocked_domain(zone_text):
    for line in zone_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("$") or stripped.startswith("@"):
            continue
        parts = stripped.split()
        if len(parts) >= 3 and parts[1].upper() == "CNAME" and parts[2] == ".":
            domain = parts[0].lstrip("*.").rstrip(".")
            if domain:
                return domain
    return None


def first_redirect_domain(zone_text):
    for line in zone_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("$") or stripped.startswith("@"):
            continue
        parts = stripped.split()
        if len(parts) >= 3 and parts[1].upper() == "CNAME" and parts[2] != ".":
            domain = parts[0].lstrip("*.").rstrip(".")
            target = parts[2].rstrip(".")
            if domain and target:
                return domain, target
    return None, None
