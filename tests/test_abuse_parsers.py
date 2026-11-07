"""Parsers de notificações de abuse. Fixtures em tests/fixtures/abuse, só com
IPs de documentação e domínios .example.

Prefixos "próprios" nos testes: 203.0.113.0/24 e 2001:db8:100::/48.
198.51.100.0/24 faz o papel de notificador/terceiros.
"""

from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.message import EmailMessage
from pathlib import Path

import pytest

from app.abuse_parsers import (
    REASON_FREE_TEXT,
    REASON_NO_SOURCE_PORT,
    REASON_NO_TIME,
    REASON_NO_TIMEZONE,
    REASON_TIMEZONE_ASSUMED,
    ParserSettings,
    classify_type,
    parse_message,
    parse_time,
)

FIXTURES = Path(__file__).parent / "fixtures" / "abuse"


def settings(**overrides):
    values = dict(
        own_prefixes=["203.0.113.0/24", "2001:db8:100::/48"],
        sender_timezones={"shadow.example": "UTC", "soc.example": "America/Sao_Paulo"},
    )
    values.update(overrides)
    return ParserSettings(**values)


def parse(name, **overrides):
    raw = (FIXTURES / name).read_bytes()
    return parse_message(message_from_bytes(raw, policy=policy.compat32), settings(**overrides))


def by_ip(result):
    return {incident.public_ip: incident for incident in result.incidents}


def test_forwarded_xarf_attachment_keeps_source_fields():
    original = message_from_bytes((FIXTURES / "xarf_json_ipv6_source_port.eml").read_bytes(), policy=policy.default)
    outer = EmailMessage()
    outer["From"] = "noc@isp.example"
    outer["Subject"] = "ENC: Abuse report"
    outer.set_content("Encaminho para processamento.")
    outer.add_attachment(original)
    result = parse_message(message_from_bytes(outer.as_bytes()), settings())
    assert result.parser == "xarf"
    assert result.sender == "noc@isp.example"
    [incident] = result.incidents
    assert incident.public_ip == "2001:db8:100::25"
    assert incident.source_port == 51515
    assert incident.occurred_at == datetime(2026, 10, 14, 10, 0)
    assert incident.status == "new"


def test_forwarded_csv_uses_original_sender_timezone():
    original = message_from_bytes((FIXTURES / "csv_no_timezone.eml").read_bytes(), policy=policy.default)
    outer = EmailMessage()
    outer["From"] = "noc@isp.example"
    outer["Subject"] = "ENC: report"
    outer.set_content("Segue anexo.")
    outer.add_attachment(original)
    result = parse_message(message_from_bytes(outer.as_bytes()), settings(sender_timezones={"unknown-tz.example": "America/Sao_Paulo"}))
    [incident] = result.incidents
    assert result.parser == "csv"
    assert incident.occurred_at == datetime(2026, 10, 14, 11, 0)
    assert incident.timezone_used == "America/Sao_Paulo"


def test_encoded_forwarded_subject_is_readable():
    outer = EmailMessage()
    outer["From"] = "noc@isp.example"
    outer["Subject"] = "ENC: Abuse report – notificação"
    outer.set_content("IP: 203.0.113.50")
    result = parse_message(message_from_bytes(outer.as_bytes()), settings())
    assert result.status == "processed"
    assert result.subject == "ENC: Abuse report – notificação"


def test_forwarded_administrative_attachment_does_not_create_incidents():
    original = EmailMessage()
    original["Subject"] = "Request to authorize Someone to view Hotmail traffic data for 203.0.113.50"
    original.set_content("Access to 203.0.113.50; fight spam.")
    outer = EmailMessage()
    outer["Subject"] = "ENC: Abuse report"
    outer.set_content("Segue anexo.")
    outer.add_attachment(original)
    assert parse_message(message_from_bytes(outer.as_bytes()), settings()).incidents == []


# --- X-ARF ------------------------------------------------------------------------

def test_xarf_v02_yaml_report():
    result = parse("xarf_v02.eml")
    assert result.parser == "xarf"
    assert result.status == "processed"
    assert result.sender == "reports@blocklist.example"
    assert result.sender_domain == "blocklist.example"
    assert result.message_id == "<xarf-1@blocklist.example>"
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.10"
    # "Port" no X-ARF é a porta atacada; não é porta de origem.
    assert incident.source_port is None
    assert incident.destination_port == 22
    assert incident.destination_ip == "198.51.100.7"
    assert incident.occurred_at == datetime(2026, 10, 14, 9, 58, 12)
    assert incident.occurred_at_raw == "2026-10-14T09:58:12+00:00"
    assert incident.timezone_used == "UTC"
    assert incident.timezone_assumed is False
    assert incident.incident_type == "brute-force"
    assert incident.raw_type == "login-attack"
    assert incident.status == "review"
    assert incident.review_reasons == [REASON_NO_SOURCE_PORT]


def test_xarf_json_ipv6_with_source_port_is_new():
    result = parse("xarf_json_ipv6_source_port.eml")
    assert result.parser == "xarf"
    [incident] = result.incidents
    assert incident.public_ip == "2001:db8:100::25"
    assert incident.source_port == 51515
    assert incident.destination_port == 443
    assert incident.occurred_at == datetime(2026, 10, 14, 10, 0, 0)
    assert incident.timezone_used == "UTC-0300"
    assert incident.incident_type == "exploit"
    assert incident.status == "new"
    assert incident.review_reasons == []


def test_xarf_with_only_third_party_ip_is_unrecognized():
    result = parse("third_party_only.eml")
    assert result.parser == "xarf"
    assert result.status == "unrecognized"
    assert result.incidents == []
    assert result.discarded_ips == 1


# --- ARF -------------------------------------------------------------------------

def test_arf_feedback_report():
    result = parse("arf.eml")
    assert result.parser == "arf"
    # A parte text/rfc822-headers tem 203.0.113.99 em Received: não pode virar incidente.
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.20"
    assert incident.source_port == 40001
    assert incident.occurred_at == datetime(2026, 10, 14, 14, 45, 0)
    assert incident.incident_type == "spam"
    assert incident.raw_type == "abuse"
    assert incident.status == "new"


# --- CSV -------------------------------------------------------------------------

def test_csv_semicolon_filters_third_parties_and_duplicates():
    result = parse("csv_semicolon.eml")
    assert result.parser == "csv"
    incidents = by_ip(result)
    assert set(incidents) == {"203.0.113.30", "203.0.113.31"}
    assert len(result.incidents) == 2  # a linha repetida foi descartada
    assert result.discarded_ips == 1  # 198.51.100.50 é de terceiro
    first = incidents["203.0.113.30"]
    assert (first.source_port, first.destination_port) == (45001, 80)
    assert first.occurred_at == datetime(2026, 10, 14, 8, 0, 0)
    assert first.incident_type == "brute-force"
    assert first.status == "new"
    second = incidents["203.0.113.31"]
    assert second.occurred_at == datetime(2026, 10, 14, 11, 5, 0)
    assert second.status == "new"


def test_shadowserver_scan_port_is_service_port():
    result = parse("shadowserver_scan.eml")
    assert result.parser == "csv"
    incidents = by_ip(result)
    v4 = incidents["203.0.113.40"]
    assert v4.source_port is None
    assert v4.destination_port == 22
    assert v4.incident_type == "open-service"
    assert v4.raw_type == "scan_ssh"
    # Shadowserver manda horário sem fuso; o fuso vem da configuração do remetente.
    assert v4.occurred_at == datetime(2026, 10, 13, 4, 11, 9)
    assert v4.timezone_used == "UTC"
    assert v4.timezone_assumed is True
    assert v4.status == "review"
    assert v4.review_reasons == [REASON_NO_SOURCE_PORT, REASON_TIMEZONE_ASSUMED]
    v6 = incidents["2001:db8:100::40"]
    assert v6.destination_port == 2222


def test_csv_without_timezone_and_unknown_sender_keeps_time_empty():
    result = parse("csv_no_timezone.eml")
    [incident] = result.incidents
    assert incident.source_port == 5000
    assert incident.occurred_at is None
    assert incident.occurred_at_raw == "2026-10-14 08:00:00"
    assert incident.timezone_used is None
    assert incident.status == "review"
    assert incident.review_reasons == [REASON_NO_TIMEZONE]
    assert incident.incident_type == "ddos"


def test_csv_without_timezone_uses_configured_sender_timezone():
    result = parse("csv_no_timezone.eml", sender_timezones={"unknown-tz.example": "America/Sao_Paulo"})
    [incident] = result.incidents
    assert incident.occurred_at == datetime(2026, 10, 14, 11, 0, 0)
    assert incident.timezone_used == "America/Sao_Paulo"
    assert incident.timezone_assumed is True
    assert incident.status == "review"
    assert incident.review_reasons == [REASON_TIMEZONE_ASSUMED]


def test_sender_timezone_matches_subdomain():
    assert settings(sender_timezones={"example": "UTC"}).timezone_for("mail.soc.example") == "UTC"
    assert settings(sender_timezones={}).timezone_for("soc.example") is None


# --- texto livre ------------------------------------------------------------------

@pytest.mark.parametrize("quote", ["", "> ", "> > "])
def test_text_source_log_extracts_port_and_utc_time(quote):
    raw = (
        "From: reports@unknown.example\nContent-Type: text/plain\n\n"
        f"{quote}2026-10-15T21:13:47Z  src port 41399  203.0.113.50 - -\n"
        f'{quote}[15/Oct/2026:23:13:47 +0200] "GET / HTTP/2.0" 429 564\n'
    ).encode()
    result = parse_message(message_from_bytes(raw), settings())
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.50"
    assert incident.source_port == 41399
    assert incident.occurred_at == datetime(2026, 10, 15, 21, 13, 47)
    assert incident.occurred_at_raw == "2026-10-15T21:13:47Z"
    assert incident.timezone_used == "UTC"
    assert incident.review_reasons == [REASON_FREE_TEXT]
    assert incident.status == "review"


def test_text_loose_ip_mention_merges_into_detailed_incident():
    raw = (
        "From: abusereport@lrob.example\nSubject: Abuse report for IP 203.0.113.50\n"
        "Content-Type: text/plain\n\n"
        "IP 203.0.113.50 from AS64500 was banned by our server on 2026-10-19 18:09:34 UTC.\n"
        "Detected attacking IP: 203.0.113.50 | From AS64500\n"
        "2026-10-19T18:09:03Z  src port 37363  203.0.113.50 - - [19/Oct/2026:20:09:03 +0200] \"GET /\"\n"
    ).encode()
    [incident] = parse_message(message_from_bytes(raw), settings()).incidents
    assert incident.source_port == 37363
    assert incident.occurred_at == datetime(2026, 10, 19, 18, 9, 3)


def test_xarf_42_with_plain_header_reads_attached_json():
    # lrob.net: "X-ARF: PLAIN" + xarf.json no formato 4.2 (snake_case).
    result = parse("xarf42_plain_lrob.eml")
    assert result.parser == "xarf"
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.247"
    assert incident.source_port == 37363
    assert incident.destination_port == 443
    assert incident.occurred_at == datetime(2026, 10, 19, 18, 9, 3)
    assert incident.raw_type == "scraping"
    assert incident.status == "new"


def test_xarf_header_other_than_yes_without_report_falls_back_to_text():
    raw = (
        "From: a@b.example\nSubject: Abuse report\nX-ARF: PLAIN\nContent-Type: text/plain\n\n"
        "2026-10-15T21:13:47Z  src port 41399  203.0.113.50 - -\n"
    ).encode()
    result = parse_message(message_from_bytes(raw), settings())
    assert result.parser == "text"
    assert result.incidents[0].source_port == 41399


def test_text_tcpdump_sample_in_forwarded_cert_mail():
    # CERT.br encaminhando NFOservers: amostras tcpdump -v no corpo e no .eml anexo,
    # vários pacotes do mesmo fluxo e destino mascarado.
    result = parse("cert_forward_tcpdump.eml")
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.199"
    assert incident.source_port == 16089
    assert (incident.destination_ip, incident.destination_port) == (None, 53)
    assert incident.occurred_at == datetime(2026, 10, 17, 18, 32, 58, 942745)
    assert incident.timezone_used == "UTC"
    assert incident.review_reasons == [REASON_FREE_TEXT]


def test_text_tcpdump_wrapped_by_outlook_forward():
    # Outlook quebra "... flags" / "[none], proto UDP ..." antes da linha do fluxo,
    # no corpo citado com "> " e no .eml anexado.
    result = parse("outlook_forward_wrapped_tcpdump.eml")
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.199"
    assert incident.source_port == 16089
    assert incident.destination_port == 53
    assert incident.occurred_at == datetime(2026, 10, 17, 18, 32, 58, 942745)


@pytest.mark.parametrize("quote", ["", " > "])
def test_text_spamcop_report_extracts_ip_and_time(quote):
    # Direto do SpamCop ou encaminhado pelo Outlook; IP em Received citado não conta.
    raw = (
        "From: <noc@isp.example>\n"
        "Subject: ENC: [SpamCop (203.0.113.76) id:7412215691]Stay In and Help Stay Coo..\n\n"
        f"{quote}[ SpamCop V5.5.0 ]\n"
        f"{quote}Email from 203.0.113.76 / Mon, 19 Oct 2026 18:08:20 +0000\n"
        f"{quote}https://www.spamcop.net/w3m?i=z7412215691z\n"
        f"{quote}\n{quote}[ Offending message ]\n"
        f"{quote}Received: from 76.113.0.203.customer.isp.example\n"
        f"{quote}(76.113.0.203.customer.isp.example [203.0.113.76])\n"
        f"{quote}designates 203.0.113.76 as permitted sender) receiver=spf.example;\n"
    ).encode()
    result = parse_message(message_from_bytes(raw), settings())
    [incident] = result.incidents
    assert incident.public_ip == "203.0.113.76"
    assert incident.occurred_at == datetime(2026, 10, 19, 18, 8, 20)
    assert incident.source_port is None
    assert incident.incident_type == "spam"
    assert incident.review_reasons == [REASON_FREE_TEXT, REASON_NO_SOURCE_PORT]


def test_text_tcpdump_single_line_without_utc_notice_uses_sender_timezone():
    raw = (
        "From: noc@soc.example\nSubject: DDoS attack\n\n"
        "2026-10-17 15:41:07.5 IP 203.0.113.199.37404 > 198.51.100.9.27015: UDP, length 1\n"
    ).encode()
    [incident] = parse_message(message_from_bytes(raw), settings()).incidents
    assert (incident.source_port, incident.destination_ip) == (37404, "198.51.100.9")
    assert incident.occurred_at == datetime(2026, 10, 17, 18, 41, 7, 500000)
    assert incident.timezone_assumed is True


@pytest.mark.parametrize("line", [
    "2026-10-15T21:13:47Z port 41399 203.0.113.50",
    "2026-10-15T21:13:47Z dst port 41399 203.0.113.50",
    "2026-10-15T21:13:47 src port 41399 203.0.113.50",
])
def test_text_does_not_guess_source_fields(line):
    result = parse_message(message_from_bytes(f"From: a@b.example\nSubject: Abuse report\n\n{line}".encode()), settings())
    [incident] = result.incidents
    assert incident.source_port is None
    assert incident.occurred_at is None


@pytest.mark.parametrize("subject,body", [
    ("Request to authorize Someone to view Hotmail traffic data for 203.0.113.50",
     "Access to 203.0.113.50. Smart Network Data Services helps fight against spam."),
    ("Network registration", "Your network is 203.0.113.50"),
    ("Service notification", "Your network is 203.0.113.50\nContact abuse@example.net for support."),
])
def test_administrative_mail_does_not_create_incidents(subject, body):
    raw = f"From: snds-authorization@outlook.com\nTo: abuse@isp.example\nSubject: {subject}\n\n{body}"
    result = parse_message(message_from_bytes(raw.encode()), settings())
    assert result.status == "unrecognized"
    assert result.incidents == []


def test_free_text_extracts_only_own_ips_and_skips_quoted_headers():
    result = parse("text_free.eml")
    assert result.parser == "text"
    incidents = by_ip(result)
    # .51 (Received), .52 e .53 (X-Originating-IP e continuação) ficam de fora.
    assert set(incidents) == {"203.0.113.50", "2001:db8:100::50"}
    for incident in incidents.values():
        # Nunca deduz porta nem horário de texto livre.
        assert incident.source_port is None
        assert incident.destination_port is None
        assert incident.occurred_at is None
        assert incident.status == "review"
        assert incident.review_reasons == [REASON_FREE_TEXT, REASON_NO_SOURCE_PORT, REASON_NO_TIME]


def test_html_only_message_without_message_id():
    result = parse("no_message_id_html.eml")
    assert result.parser == "text"
    assert result.message_id is None
    assert result.received_at is None
    assert [i.public_ip for i in result.incidents] == ["203.0.113.70"]


def test_no_own_prefixes_makes_everything_unrecognized():
    result = parse("csv_semicolon.eml", own_prefixes=[])
    assert result.status == "unrecognized"
    assert result.discarded_ips == 4
    assert "Nenhum prefixo próprio configurado" in result.notes


def test_received_at_is_utc():
    assert parse("arf.eml").received_at == datetime(2026, 10, 14, 15, 0, 0)


# --- horário e tipo ----------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected_utc, explicit",
    [
        ("2026-10-14T09:58:12Z", datetime(2026, 10, 14, 9, 58, 12), True),
        ("2026-10-14 09:58:12 UTC", datetime(2026, 10, 14, 9, 58, 12), True),
        ("2026-10-14 09:58:12 GMT", datetime(2026, 10, 14, 9, 58, 12), True),
        ("2026-10-14 06:58:12 -0300", datetime(2026, 10, 14, 9, 58, 12), True),
        ("Wed, 14 Oct 2026 06:58:12 -0300", datetime(2026, 10, 14, 9, 58, 12), True),
        ("1791971892", datetime(2026, 10, 14, 9, 58, 12), True),
        ("2026-10-14 09:58:12", None, False),
        ("14/10/2026 09:58:12", None, False),
        ("Wed, 14 Oct 2026 09:58:12 -0000", None, False),
    ],
)
def test_parse_time(raw, expected_utc, explicit):
    value, is_explicit = parse_time(raw)
    assert value is not None
    assert is_explicit is explicit
    if explicit:
        assert value.astimezone(timezone.utc).replace(tzinfo=None) == expected_utc


@pytest.mark.parametrize("raw", ["", "ontem à tarde", "99/99/9999"])
def test_parse_time_rejects_garbage(raw):
    assert parse_time(raw) == (None, False)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("ssh-bruteforce", "brute-force"),
        ("login-attack", "brute-force"),
        ("portscan", "scan"),
        ("scanning", "scan"),
        ("scan_ssh", "open-service"),
        ("open-resolver", "open-service"),
        ("ddos", "ddos"),
        ("botnet-drone", "botnet"),
        ("event4_sinkhole", "botnet"),
        ("phishing", "phishing"),
        ("spam", "spam"),
        ("DMCA notice", "copyright"),
        ("sql-injection", "exploit"),
        ("Open-Service", "open-service"),
        ("weird", "other"),
        (None, "other"),
    ],
)
def test_classify_type(raw, expected):
    assert classify_type(raw) == expected
