"""Importação do fixed-nat do A10. Os arquivos são gerados aqui, no mesmo
formato do equipamento, com IPs de documentação no lado público."""

import ipaddress

import pytest

from app.cgnat_import import CgnatImportError, main, parse_a10_fixed_nat


def a10_file(public, private, first_port, ports, allocation="interleaved", method="use-all-nat-ips"):
    public_net = ipaddress.IPv4Network(public)
    private_net = ipaddress.IPv4Network(private)
    p = public_net.num_addresses
    blocks = (65536 - first_port) // ports
    lines = [
        "Fixed NAT Configuration was created at 2026 Jan 01 00:00:00",
        "cgnv6 fixed-nat inside ip-list POOL-INSIDE-T nat ip-list POOL-OUTSIDE-T "
        f"dest-rule-list BYPASS respond-to-user-mac method {method} vrid 1",
    ]
    for pub_off in range(p):
        lines.append(f"NAT Address: {public_net.network_address + pub_off}")
        lines.append("Inside User         Port Range")
        for block in range(blocks):
            idx = block * p + pub_off if allocation == "interleaved" else pub_off * blocks + block
            start = first_port + block * ports
            lines.append(f"{private_net.network_address + idx}          {start} to {start + ports - 1}")
    lines += ["", "MD5 SUM: 0123456789abcdef0123456789abcdef"]
    return "\n".join(lines) + "\n"


def test_full_size_pool_like_production():
    text = a10_file("198.51.100.0/24", "100.64.0.0/19", 1024, 2016)
    pool = parse_a10_fixed_nat(text)
    assert pool.pool_name == "POOL-OUTSIDE-T"
    assert pool.method == "use-all-nat-ips"
    assert pool.public_prefix == "198.51.100.0/24"
    assert pool.private_prefix == "100.64.0.0/19"
    assert (pool.first_port, pool.ports_per_subscriber) == (1024, 2016)
    assert pool.allocation == "interleaved"
    assert pool.entry_count == 8192
    assert pool.md5 == "0123456789abcdef0123456789abcdef"
    assert pool.exported_at == "2026 Jan 01 00:00:00"
    assert pool.warnings == []


def test_sequential_file_is_detected():
    text = a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128, allocation="sequential", method="other")
    assert parse_a10_fixed_nat(text).allocation == "sequential"


def test_single_wrong_line_rejects_the_file():
    text = a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128)
    # Troca dois assinantes de lugar: nenhuma das duas fórmulas explica.
    text = text.replace("100.64.0.1          1024", "100.64.0.X", 1)
    text = text.replace("100.64.0.5          17152", "100.64.0.1          17152", 1)
    text = text.replace("100.64.0.X", "100.64.0.5          1024", 1)
    with pytest.raises(CgnatImportError, match="alocação"):
        parse_a10_fixed_nat(text)


def test_missing_subscriber_rejects_the_file():
    text = a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128)
    lines = [line for line in text.splitlines() if not line.startswith("100.64.0.7 ")]
    with pytest.raises(CgnatImportError):
        parse_a10_fixed_nat("\n".join(lines))


def test_unknown_line_rejects_the_file():
    text = a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128) + "algo inesperado\n"
    with pytest.raises(CgnatImportError, match="não reconhecida"):
        parse_a10_fixed_nat(text)


def test_mixed_block_sizes_rejected():
    text = a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128)
    text = text.replace("1024 to 17151", "1024 to 17150", 1)
    with pytest.raises(CgnatImportError, match="portas"):
        parse_a10_fixed_nat(text)


def test_empty_or_other_file_rejected():
    with pytest.raises(CgnatImportError):
        parse_a10_fixed_nat("")
    with pytest.raises(CgnatImportError):
        parse_a10_fixed_nat("Fixed NAT Configuration was created at 2026 Jan 01 00:00:00\n")


def test_cli_checks_files(tmp_path, capsys):
    good = tmp_path / "good.txt"
    good.write_text(a10_file("203.0.113.0/30", "100.64.0.0/28", 1024, 16128), encoding="utf-8")
    bad = tmp_path / "bad.txt"
    bad.write_text("lixo\n", encoding="utf-8")
    assert main([str(good)]) == 0
    assert main([str(good), str(bad)]) == 1
    out = capsys.readouterr().out
    assert "OK POOL-OUTSIDE-T 203.0.113.0/30 <- 100.64.0.0/28 interleaved" in out
    assert "ERRO" in out
