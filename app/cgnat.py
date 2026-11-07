"""Cálculo do CGNAT determinístico (funções puras, sem banco).

Uma regra liga um prefixo privado a um prefixo público. Cada IP público é
dividido em blocos de ``ports_per_subscriber`` portas a partir de
``first_port``; cada assinante (IP privado) recebe um bloco de um IP público.

Modos de alocação, com ``idx`` = posição do IP privado no prefixo privado,
``P`` = quantidade de IPs públicos e ``B`` = blocos por IP público:

- ``interleaved`` (A10 ``method use-all-nat-ips``): IPs privados consecutivos
  saem por IPs públicos diferentes. ``público = idx % P``, ``bloco = idx // P``.
- ``sequential``: IPs privados consecutivos ocupam os blocos de um mesmo IP
  público antes de passar ao próximo. ``público = idx // B``, ``bloco = idx % B``.

As funções aceitam qualquer objeto com os atributos de ``CgnatRule``
(``private_prefix``, ``public_prefix``, ``ports_per_subscriber``,
``first_port``, ``allocation``, ``valid_from``, ``valid_to``). Horários são
``datetime`` UTC sem fuso, como no resto do sistema.
"""

import ipaddress
from dataclasses import dataclass
from datetime import datetime

ALLOCATIONS = ("interleaved", "sequential")
MAX_PORT = 65535


class CgnatRuleError(ValueError):
    """Regra com parâmetros inconsistentes."""


class CgnatRuleConflict(ValueError):
    """Regras com o mesmo prefixo e vigências sobrepostas."""


@dataclass(frozen=True)
class PrivateMapping:
    private_ip: str
    public_ip: str
    port_start: int
    port_end: int
    block: int
    rule: object


@dataclass(frozen=True)
class PublicMapping:
    public_ip: str
    port_start: int
    port_end: int
    block: int
    rule: object


def _networks(rule):
    try:
        private = ipaddress.IPv4Network(rule.private_prefix, strict=True)
        public = ipaddress.IPv4Network(rule.public_prefix, strict=True)
    except ValueError as exc:
        raise CgnatRuleError(f"Prefixo inválido: {exc}") from exc
    return private, public


def blocks_per_ip(rule):
    return (MAX_PORT + 1 - rule.first_port) // rule.ports_per_subscriber


def validate_rule(rule):
    """Confere a geometria da regra. Lança ``CgnatRuleError`` se não fechar."""
    if rule.allocation not in ALLOCATIONS:
        raise CgnatRuleError(f"Alocação desconhecida: {rule.allocation!r}")
    if not 0 < rule.first_port <= MAX_PORT:
        raise CgnatRuleError("Porta inicial fora de 1..65535")
    if rule.ports_per_subscriber <= 0:
        raise CgnatRuleError("Portas por assinante deve ser positivo")
    blocks = blocks_per_ip(rule)
    if blocks < 1:
        raise CgnatRuleError("Não cabe nenhum bloco de portas após a porta inicial")
    private, public = _networks(rule)
    capacity = public.num_addresses * blocks
    if private.num_addresses != capacity:
        raise CgnatRuleError(
            f"Prefixo privado tem {private.num_addresses} endereços, mas o público "
            f"comporta {public.num_addresses} x {blocks} blocos = {capacity} assinantes"
        )
    if rule.valid_to is not None and rule.valid_to <= rule.valid_from:
        raise CgnatRuleError("Fim da vigência deve ser depois do início")


def is_active(rule, when):
    return rule.valid_from <= when and (rule.valid_to is None or when < rule.valid_to)


def _single_rule(candidates, what):
    if len(candidates) > 1:
        raise CgnatRuleConflict(f"Mais de uma regra vigente para {what}")
    return candidates[0] if candidates else None


def find_rule_for_public(public_ip, when, rules):
    ip = ipaddress.ip_address(public_ip)
    candidates = [
        rule
        for rule in rules
        if is_active(rule, when)
        and ip.version == 4
        and ip in ipaddress.IPv4Network(rule.public_prefix)
    ]
    return _single_rule(candidates, public_ip)


def find_rule_for_private(private_ip, when, rules):
    ip = ipaddress.ip_address(private_ip)
    candidates = [
        rule
        for rule in rules
        if is_active(rule, when)
        and ip.version == 4
        and ip in ipaddress.IPv4Network(rule.private_prefix)
    ]
    return _single_rule(candidates, private_ip)


def public_to_private(public_ip, port, when, rules):
    """IP público + porta de origem + instante UTC -> ``PrivateMapping`` ou None.

    None quando não há regra vigente para o IP no instante, ou a porta não
    pertence a nenhum bloco (abaixo da porta inicial ou na sobra final).
    """
    if port is None or when is None:
        return None
    rule = find_rule_for_public(public_ip, when, rules)
    if rule is None:
        return None
    private, public = _networks(rule)
    port = int(port)
    if port < rule.first_port or port > MAX_PORT:
        return None
    blocks = blocks_per_ip(rule)
    block = (port - rule.first_port) // rule.ports_per_subscriber
    if block >= blocks:
        return None
    public_offset = int(ipaddress.ip_address(public_ip)) - int(public.network_address)
    if rule.allocation == "interleaved":
        idx = block * public.num_addresses + public_offset
    else:
        idx = public_offset * blocks + block
    port_start = rule.first_port + block * rule.ports_per_subscriber
    return PrivateMapping(
        private_ip=str(private.network_address + idx),
        public_ip=str(ipaddress.ip_address(public_ip)),
        port_start=port_start,
        port_end=port_start + rule.ports_per_subscriber - 1,
        block=block,
        rule=rule,
    )


def private_to_public(private_ip, when, rules):
    """IP privado + instante UTC -> IP público e faixa de portas, ou None."""
    if when is None:
        return None
    rule = find_rule_for_private(private_ip, when, rules)
    if rule is None:
        return None
    private, public = _networks(rule)
    idx = int(ipaddress.ip_address(private_ip)) - int(private.network_address)
    blocks = blocks_per_ip(rule)
    if rule.allocation == "interleaved":
        public_offset, block = idx % public.num_addresses, idx // public.num_addresses
    else:
        public_offset, block = idx // blocks, idx % blocks
    port_start = rule.first_port + block * rule.ports_per_subscriber
    return PublicMapping(
        public_ip=str(public.network_address + public_offset),
        port_start=port_start,
        port_end=port_start + rule.ports_per_subscriber - 1,
        block=block,
        rule=rule,
    )


def _periods_overlap(a_from, a_to, b_from, b_to):
    return (b_to is None or a_from < b_to) and (a_to is None or b_from < a_to)


def _prefixes_overlap(a, b):
    a_private, a_public = _networks(a)
    b_private, b_public = _networks(b)
    return a_public.overlaps(b_public) or a_private.overlaps(b_private)


def plan_rule_insertion(existing, new_rules):
    """Valida a entrada de novas regras e diz quais vigentes devem ser encerradas.

    Uma regra existente em aberto (sem fim) e iniciada antes da nova é
    encerrada no início da nova; é o caso normal de importar um arquivo novo
    do equipamento. Qualquer outra sobreposição de prefixo e período é
    conflito. Retorna ``[(regra_existente, novo_valid_to), ...]``.
    """
    for rule in new_rules:
        validate_rule(rule)
    for i, a in enumerate(new_rules):
        for b in new_rules[i + 1:]:
            if _prefixes_overlap(a, b) and _periods_overlap(
                a.valid_from, a.valid_to, b.valid_from, b.valid_to
            ):
                raise CgnatRuleConflict(
                    f"Regras novas sobrepostas: {a.public_prefix} e {b.public_prefix}"
                )

    closings = {}
    for new in new_rules:
        for old in existing:
            if not _prefixes_overlap(new, old):
                continue
            old_to = closings.get(id(old), (old, old.valid_to))[1]
            if not _periods_overlap(new.valid_from, new.valid_to, old.valid_from, old_to):
                continue
            if old.valid_to is None and old.valid_from < new.valid_from and new.valid_to is None:
                closings[id(old)] = (old, new.valid_from)
                continue
            raise CgnatRuleConflict(
                f"Vigência sobreposta com a regra {old.public_prefix} "
                f"({_fmt(old.valid_from)} até {_fmt(old.valid_to)})"
            )
    return list(closings.values())


def _fmt(value):
    return value.strftime("%Y-%m-%d %H:%M") if isinstance(value, datetime) else "em aberto"
