"""Servidores BIND e roteadores (com credenciais SSH) cadastrados em Geral > Parâmetros.

Ficam como listas JSON em ParameterSettings. As senhas nunca saem pela API: o
formulário recebe só "<campo>_set" e, ao salvar, campo vazio mantém a senha atual.
"""

import json
import os
import secrets

ROUTER_FIELDS = ("name", "host", "port", "user", "password", "key_path", "key_passphrase")
BIND_FIELDS = ROUTER_FIELDS + ("sudo_password", "remote_path", "reload_command", "test_resolver")
SECRET_FIELDS = ("password", "key_passphrase", "sudo_password")

BIND_DEFAULTS = {
    "remote_path": "/var/cache/bind/db.rpz.zone",
    "reload_command": "sudo service bind9 reload",
    "test_resolver": "127.0.0.1",
}

KIND_LABELS = {"bind": "servidor BIND", "router": "roteador"}


def fields_for(kind):
    return BIND_FIELDS if kind == "bind" else ROUTER_FIELDS


def normalize_target(item, kind):
    fields = fields_for(kind)
    target = {"id": str(item.get("id") or "").strip() or secrets.token_hex(8)}
    for field in fields:
        value = item.get(field)
        if field == "port":
            target[field] = parse_port(value)
        elif field in SECRET_FIELDS:
            target[field] = str(value) if value else ""
        else:
            target[field] = str(value or "").strip()
    target["name"] = target["name"] or target["host"]
    if kind == "bind":
        for field, default in BIND_DEFAULTS.items():
            target[field] = target[field] or default
    return target


def parse_port(value):
    try:
        port = int(value or 22)
    except (TypeError, ValueError):
        return 22
    return port if 1 <= port <= 65535 else 22


def load_targets(value, kind):
    """Lista completa (com senhas) para uso interno na publicação."""
    if not value:
        return []
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [
        normalize_target(item, kind)
        for item in loaded
        if isinstance(item, dict) and str(item.get("host") or "").strip()
    ]


def dump_targets(targets):
    return json.dumps(targets)


def public_targets(targets):
    """Versão para a API: sem senhas, só se cada uma está definida."""
    result = []
    for target in targets:
        item = {key: value for key, value in target.items() if key not in SECRET_FIELDS}
        for field in SECRET_FIELDS:
            if field in target:
                item[f"{field}_set"] = bool(target[field])
        result.append(item)
    return result


def merge_targets(payload, existing, kind):
    """Valida a lista vinda do formulário, mantendo as senhas não reenviadas.

    Cada item pode trazer "clear": ["password", ...] para apagar uma senha salva.
    Levanta ValueError com mensagem para o usuário.
    """
    if payload is None:
        return existing
    if not isinstance(payload, list):
        raise ValueError(f"Lista de {KIND_LABELS[kind]}es inválida.")

    existing_by_id = {target["id"]: target for target in existing}
    label = KIND_LABELS[kind]
    targets = []
    for position, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"{label.capitalize()} {position} inválido.")
        if not any(str(item.get(field) or "").strip() for field in ("name", "host", "user")):
            continue  # linha em branco

        previous = existing_by_id.get(str(item.get("id") or ""), {})
        clear = item.get("clear") if isinstance(item.get("clear"), list) else []
        merged = dict(item)
        for field in SECRET_FIELDS:
            if field not in fields_for(kind):
                continue
            if field in clear:
                merged[field] = ""
            elif not item.get(field):
                merged[field] = previous.get(field, "")
        merged["id"] = previous.get("id") or ""

        reference = str(item.get("name") or item.get("host") or position).strip()
        if not str(item.get("host") or "").strip():
            raise ValueError(f"Informe o IP/host do {label} {reference}.")
        try:
            port = int(item.get("port") or 22)
        except (TypeError, ValueError):
            port = 0
        if not 1 <= port <= 65535:
            raise ValueError(f"Porta SSH do {label} {reference} deve estar entre 1 e 65535.")
        merged["port"] = port

        target = normalize_target(merged, kind)
        if not target["user"]:
            raise ValueError(f"Informe o usuário SSH do {label} {target['name']}.")
        if not target["password"] and not target["key_path"]:
            raise ValueError(f"Informe a senha ou o caminho da chave SSH do {label} {target['name']}.")
        targets.append(target)
    return targets


def legacy_env_targets(routers):
    """Até a versão 1.3.2 o BIND e as credenciais SSH vinham do .env. Monta o
    equivalente para importar uma única vez para Parâmetros."""
    env = os.getenv
    servers = []
    if env("SSH_HOST") and env("SSH_USER"):
        servers.append(
            normalize_target(
                {
                    "host": env("SSH_HOST"),
                    "port": env("SSH_PORT"),
                    "user": env("SSH_USER"),
                    "password": env("SSH_PASSWORD"),
                    "key_path": env("SSH_KEY_PATH"),
                    "key_passphrase": env("SSH_KEY_PASSPHRASE"),
                    "sudo_password": env("SUDO_PASSWORD"),
                    "remote_path": env("RPZ_REMOTE_PATH"),
                    "reload_command": env("RPZ_RELOAD_COMMAND"),
                    "test_resolver": env("RPZ_TEST_RESOLVER"),
                },
                "bind",
            )
        )

    router_env = {
        "port": env("ROUTER_SSH_PORT") or env("SSH_PORT"),
        "user": env("ROUTER_SSH_USER") or env("SSH_USER"),
        "password": env("ROUTER_SSH_PASSWORD") or env("SSH_PASSWORD"),
        "key_path": env("ROUTER_SSH_KEY_PATH") or env("SSH_KEY_PATH"),
        "key_passphrase": env("ROUTER_SSH_KEY_PASSPHRASE") or env("SSH_KEY_PASSPHRASE"),
    }
    routers = list(routers)
    if not routers and env("ROUTER_SSH_HOST"):
        routers = [{"host": env("ROUTER_SSH_HOST")}]
    imported_routers = []
    for router in routers:
        merged = dict(router)
        for field, value in router_env.items():
            if not merged.get(field) and value:
                merged[field] = value
        imported_routers.append(normalize_target(merged, "router"))

    strict = env("SSH_STRICT_HOST_KEY_CHECKING", "false").lower() in {"1", "true", "yes"}
    return servers, imported_routers, strict


def has_legacy_env():
    return any(
        os.getenv(name)
        for name in ("SSH_HOST", "SSH_USER", "ROUTER_SSH_HOST", "ROUTER_SSH_USER", "RPZ_NAMESERVER")
    )
