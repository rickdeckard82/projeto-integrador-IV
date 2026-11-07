"""Regra CGNAT. Só IPs de documentação no lado público (198.51.100.0/24,
203.0.113.0/24) e 100.64.0.0/10 (faixa reservada a CGNAT) no lado privado."""

from datetime import datetime
from types import SimpleNamespace

import pytest

from app.cgnat import (
    CgnatRuleConflict,
    CgnatRuleError,
    plan_rule_insertion,
    private_to_public,
    public_to_private,
    validate_rule,
)

T0 = datetime(2026, 1, 1)
T1 = datetime(2026, 6, 1)
INSIDE = datetime(2026, 3, 15, 12, 0)


def rule(**overrides):
    # Mesma geometria de um pool do A10: /24 público, /19 privado, 32 blocos de 2016.
    values = dict(
        private_prefix="100.64.0.0/19",
        public_prefix="198.51.100.0/24",
        ports_per_subscriber=2016,
        first_port=1024,
        allocation="interleaved",
        valid_from=T0,
        valid_to=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def small_rule(**overrides):
    # 4 IPs públicos x 4 blocos de 16128 portas = 16 assinantes (/28).
    values = dict(
        private_prefix="100.64.0.0/28",
        public_prefix="203.0.113.0/30",
        ports_per_subscriber=16128,
        first_port=1024,
    )
    values.update(overrides)
    return rule(**values)


# --- bordas do bloco de portas -------------------------------------------------

def test_first_port_of_first_block():
    m = public_to_private("198.51.100.0", 1024, INSIDE, [rule()])
    assert (m.private_ip, m.port_start, m.port_end, m.block) == ("100.64.0.0", 1024, 3039, 0)


def test_last_port_of_first_block():
    assert public_to_private("198.51.100.0", 3039, INSIDE, [rule()]).private_ip == "100.64.0.0"


def test_first_port_of_second_block_changes_subscriber():
    assert public_to_private("198.51.100.0", 3040, INSIDE, [rule()]).private_ip == "100.64.1.0"


def test_last_port_of_last_block():
    m = public_to_private("198.51.100.255", 65535, INSIDE, [rule()])
    assert (m.private_ip, m.port_start, m.port_end, m.block) == ("100.64.31.255", 63520, 65535, 31)


def test_example_inside_block():
    # Exemplo conferido com o arquivo real: .37 porta 45380 -> bloco 22.
    m = public_to_private("198.51.100.37", 45380, INSIDE, [rule()])
    assert (m.private_ip, m.port_start, m.port_end) == ("100.64.22.37", 45376, 47391)


@pytest.mark.parametrize("port", [0, 1, 80, 1023])
def test_port_below_first_port(port):
    assert public_to_private("198.51.100.10", port, INSIDE, [rule()]) is None


def test_port_in_leftover_after_last_full_block():
    # 64512 // 16000 = 4 blocos (1024..65023); a sobra 65024..65535 não é de ninguém.
    r = rule(ports_per_subscriber=16000, private_prefix="100.64.0.0/22")
    validate_rule(r)
    assert public_to_private("198.51.100.0", 65023, INSIDE, [r]).block == 3
    assert public_to_private("198.51.100.0", 65024, INSIDE, [r]) is None
    assert public_to_private("198.51.100.0", 65535, INSIDE, [r]) is None


def test_missing_port_or_time_returns_none():
    assert public_to_private("198.51.100.1", None, INSIDE, [rule()]) is None
    assert public_to_private("198.51.100.1", 2000, None, [rule()]) is None


# --- pool ------------------------------------------------------------------------

def test_first_and_last_public_ip_of_pool():
    assert public_to_private("198.51.100.0", 1024, INSIDE, [rule()]).private_ip == "100.64.0.0"
    assert public_to_private("198.51.100.255", 1024, INSIDE, [rule()]).private_ip == "100.64.0.255"


@pytest.mark.parametrize("ip", ["198.51.101.0", "203.0.113.5", "2001:db8::1"])
def test_ip_outside_pool(ip):
    assert public_to_private(ip, 2000, INSIDE, [rule()]) is None


# --- vigência --------------------------------------------------------------------

def test_before_validity():
    assert public_to_private("198.51.100.1", 2000, datetime(2025, 12, 31, 23, 59, 59), [rule()]) is None


def test_exact_start_of_validity_is_included():
    assert public_to_private("198.51.100.1", 2000, T0, [rule()]) is not None


def test_end_of_validity_is_excluded():
    r = rule(valid_to=T1)
    assert public_to_private("198.51.100.1", 2000, datetime(2026, 5, 31, 23, 59), [r]) is not None
    assert public_to_private("198.51.100.1", 2000, T1, [r]) is None


def test_adjacent_rules_pick_the_right_one():
    old = rule(valid_to=T1)
    new = rule(valid_from=T1, private_prefix="100.64.32.0/19")
    rules = [old, new]
    assert public_to_private("198.51.100.1", 1024, datetime(2026, 5, 31), rules).private_ip == "100.64.0.1"
    assert public_to_private("198.51.100.1", 1024, T1, rules).private_ip == "100.64.32.1"


def test_overlapping_active_rules_are_rejected_at_lookup():
    with pytest.raises(CgnatRuleConflict):
        public_to_private("198.51.100.1", 2000, INSIDE, [rule(), rule()])


# --- alocação --------------------------------------------------------------------

def test_sequential_allocation():
    r = small_rule(allocation="sequential")
    # IPs privados consecutivos ocupam os blocos do mesmo público.
    assert public_to_private("203.0.113.0", 1024, INSIDE, [r]).private_ip == "100.64.0.0"
    assert public_to_private("203.0.113.0", 1024 + 16128, INSIDE, [r]).private_ip == "100.64.0.1"
    assert public_to_private("203.0.113.1", 1024, INSIDE, [r]).private_ip == "100.64.0.4"


def test_interleaved_allocation():
    r = small_rule()
    assert public_to_private("203.0.113.1", 1024, INSIDE, [r]).private_ip == "100.64.0.1"
    assert public_to_private("203.0.113.0", 1024 + 16128, INSIDE, [r]).private_ip == "100.64.0.4"


@pytest.mark.parametrize("allocation", ["interleaved", "sequential"])
def test_round_trip_every_subscriber(allocation):
    r = small_rule(allocation=allocation)
    seen = set()
    for idx in range(16):
        private = f"100.64.0.{idx}"
        pub = private_to_public(private, INSIDE, [r])
        for port in (pub.port_start, pub.port_end):
            assert public_to_private(pub.public_ip, port, INSIDE, [r]).private_ip == private
        seen.add((pub.public_ip, pub.port_start))
    assert len(seen) == 16


# --- validação da regra -----------------------------------------------------------

@pytest.mark.parametrize(
    "overrides",
    [
        {"allocation": "random"},
        {"first_port": 0},
        {"ports_per_subscriber": 0},
        {"ports_per_subscriber": 70000},
        {"private_prefix": "100.64.0.0/20"},  # metade do que o público comporta
        {"public_prefix": "198.51.100.1/24"},  # prefixo com bits de host
        {"valid_to": T0},
    ],
)
def test_invalid_rules(overrides):
    with pytest.raises(CgnatRuleError):
        validate_rule(rule(**overrides))


def test_plan_closes_open_rule_on_new_import():
    old = rule()
    new = rule(valid_from=T1)
    assert plan_rule_insertion([old], [new]) == [(old, T1)]


def test_plan_four_pools_close_matching_old_pools_only():
    old_a = rule()
    old_b = rule(public_prefix="203.0.113.0/24", private_prefix="100.64.32.0/19")
    new_a = rule(valid_from=T1)
    closings = plan_rule_insertion([old_a, old_b], [new_a])
    assert closings == [(old_a, T1)]


def test_plan_rejects_new_rule_starting_before_open_rule():
    with pytest.raises(CgnatRuleConflict):
        plan_rule_insertion([rule(valid_from=T1)], [rule(valid_from=T0)])


def test_plan_rejects_overlap_with_closed_period():
    with pytest.raises(CgnatRuleConflict):
        plan_rule_insertion([rule(valid_to=T1)], [rule(valid_from=datetime(2026, 3, 1))])


def test_plan_accepts_adjacent_closed_period():
    assert plan_rule_insertion([rule(valid_to=T1)], [rule(valid_from=T1)]) == []


def test_plan_rejects_overlapping_new_rules():
    with pytest.raises(CgnatRuleConflict):
        plan_rule_insertion([], [rule(), rule(public_prefix="203.0.113.0/24")])
