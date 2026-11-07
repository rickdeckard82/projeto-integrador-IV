"""Leitura do arquivo de fixed-nat exportado pelo A10 Thunder.

O arquivo (``fixed_nat_ip_list_<POOL>_<data>.txt``) lista, para cada IP
público, o IP privado e a faixa de portas de cada assinante. A partir dele
inferimos os parâmetros da regra (prefixos, porta inicial, portas por
assinante e modo de alocação) e conferimos a regra contra **todas** as
linhas: se uma única linha não bater com a fórmula, a importação é recusada.
"""

import ipaddress
import re
from datetime import datetime
from dataclasses import dataclass, field
from types import SimpleNamespace

from .cgnat import ALLOCATIONS, CgnatRuleError, blocks_per_ip, private_to_public, validate_rule

COMMAND_RE = re.compile(r"^cgnv6\s+fixed-nat\s+inside\s+.*$", re.IGNORECASE)
NAT_LIST_RE = re.compile(r"\bnat\s+ip-list\s+(\S+)", re.IGNORECASE)
METHOD_RE = re.compile(r"\bmethod\s+(\S+)", re.IGNORECASE)
NAT_ADDRESS_RE = re.compile(r"^NAT Address:\s*(\S+)\s*$", re.IGNORECASE)
ENTRY_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+to\s+(\d+)\s*$", re.IGNORECASE)
MD5_RE = re.compile(r"^MD5 SUM:\s*([0-9a-fA-F]{32})\s*$")
CREATED_RE = re.compile(r"^Fixed NAT Configuration was created at\s+(.+?)\s*$", re.IGNORECASE)


class CgnatImportError(ValueError):
    """Arquivo ilegível ou que não corresponde a nenhuma fórmula conhecida."""


@dataclass
class ImportedPool:
    pool_name: str | None
    method: str | None
    exported_at: str | None
    md5: str | None
    private_prefix: str
    public_prefix: str
    first_port: int
    ports_per_subscriber: int
    allocation: str
    entry_count: int
    warnings: list = field(default_factory=list)


def _single_network(addresses, label):
    addresses = sorted(set(addresses))
    first, last = addresses[0], addresses[-1]
    networks = list(ipaddress.summarize_address_range(first, last))
    if len(networks) != 1:
        raise CgnatImportError(f"Os IPs {label} não formam um único prefixo CIDR")
    network = networks[0]
    if network.num_addresses != len(addresses):
        raise CgnatImportError(
            f"Faltam IPs {label} no arquivo: {len(addresses)} de {network.num_addresses} em {network}"
        )
    return network


def parse_a10_fixed_nat(text):
    """Lê o conteúdo do arquivo e devolve um ``ImportedPool`` conferido."""
    pool_name = method = exported_at = md5 = None
    current_public = None
    entries = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.lower().startswith("inside user"):
            continue
        if match := CREATED_RE.match(line):
            exported_at = match.group(1)
        elif COMMAND_RE.match(line):
            if m := NAT_LIST_RE.search(line):
                pool_name = m.group(1)
            if m := METHOD_RE.search(line):
                method = m.group(1).lower()
        elif match := NAT_ADDRESS_RE.match(line):
            try:
                current_public = ipaddress.IPv4Address(match.group(1))
            except ValueError as exc:
                raise CgnatImportError(f"Linha {number}: IP público inválido") from exc
        elif match := ENTRY_RE.match(line):
            if current_public is None:
                raise CgnatImportError(f"Linha {number}: assinante antes de 'NAT Address'")
            try:
                private = ipaddress.IPv4Address(match.group(1))
            except ValueError as exc:
                raise CgnatImportError(f"Linha {number}: IP privado inválido") from exc
            start, end = int(match.group(2)), int(match.group(3))
            if not 0 < start <= end <= 65535:
                raise CgnatImportError(f"Linha {number}: faixa de portas inválida")
            entries.append((private, current_public, start, end, number))
        elif match := MD5_RE.match(line):
            md5 = match.group(1).lower()
        else:
            raise CgnatImportError(f"Linha {number} não reconhecida: {line[:80]}")

    if not entries:
        raise CgnatImportError("Nenhum mapeamento encontrado; não parece um arquivo de fixed-nat do A10")

    sizes = {end - start + 1 for _, _, start, end, _ in entries}
    if len(sizes) != 1:
        raise CgnatImportError("Assinantes com quantidades de portas diferentes; formato não suportado")
    ports_per_subscriber = sizes.pop()
    first_port = min(start for _, _, start, _, _ in entries)

    privates = [entry[0] for entry in entries]
    if len(set(privates)) != len(privates):
        raise CgnatImportError("IP privado repetido no arquivo")
    private_net = _single_network(privates, "privados")
    public_net = _single_network([entry[1] for entry in entries], "públicos")

    warnings = []
    allocation = None
    for candidate in ALLOCATIONS:
        rule = SimpleNamespace(
            private_prefix=str(private_net),
            public_prefix=str(public_net),
            ports_per_subscriber=ports_per_subscriber,
            first_port=first_port,
            allocation=candidate,
            valid_from=None,
            valid_to=None,
        )
        try:
            validate_rule_geometry(rule)
        except CgnatRuleError as exc:
            raise CgnatImportError(str(exc)) from exc
        if all(_entry_matches(rule, entry) for entry in entries):
            allocation = candidate
            break
    if allocation is None:
        raise CgnatImportError(
            "O mapeamento do arquivo não segue a alocação intercalada nem a sequencial; "
            "a fórmula do equipamento precisa ser analisada antes de importar"
        )

    if method == "use-all-nat-ips" and allocation != "interleaved":
        warnings.append("Método use-all-nat-ips com alocação sequencial: confira o arquivo")

    return ImportedPool(
        pool_name=pool_name,
        method=method,
        exported_at=exported_at,
        md5=md5,
        private_prefix=str(private_net),
        public_prefix=str(public_net),
        first_port=first_port,
        ports_per_subscriber=ports_per_subscriber,
        allocation=allocation,
        entry_count=len(entries),
        warnings=warnings,
    )


def validate_rule_geometry(rule):
    """``validate_rule`` sem a parte de vigência (o arquivo não traz datas)."""
    probe = SimpleNamespace(**vars(rule))
    probe.valid_from = datetime(2000, 1, 1)
    probe.valid_to = None
    validate_rule(probe)
    return blocks_per_ip(rule)


def _entry_matches(rule, entry):
    private, public, start, end, _ = entry
    probe = SimpleNamespace(**vars(rule))
    probe.valid_from = datetime(2000, 1, 1)
    mapping = private_to_public(str(private), datetime(2000, 1, 2), [probe])
    return (
        mapping is not None
        and mapping.public_ip == str(public)
        and mapping.port_start == start
        and mapping.port_end == end
    )


def main(argv=None):
    """``python -m app.cgnat_import ARQUIVO...``: confere arquivos sem gravar nada."""
    import sys

    paths = argv if argv is not None else sys.argv[1:]
    status = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="strict") as handle:
                pool = parse_a10_fixed_nat(handle.read())
        except (OSError, UnicodeDecodeError, CgnatImportError) as exc:
            print(f"{path}: ERRO: {exc}")
            status = 1
            continue
        print(
            f"{path}: OK {pool.pool_name or '-'} {pool.public_prefix} <- {pool.private_prefix} "
            f"{pool.allocation}, porta inicial {pool.first_port}, "
            f"{pool.ports_per_subscriber} portas/assinante, {pool.entry_count} linhas conferidas"
        )
        for warning in pool.warnings:
            print(f"  aviso: {warning}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
