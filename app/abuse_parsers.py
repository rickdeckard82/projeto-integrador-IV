"""Extração de incidentes das notificações de abuse (funções puras, sem banco).

Ordem de tentativa, parando no primeiro formato reconhecido:

1. X-ARF (cabeçalho ``X-ARF: yes`` + parte com o relatório YAML/JSON);
2. ARF / RFC 5965 (parte ``message/feedback-report``);
3. CSV anexado (delimitador detectado);
4. texto livre (sempre vai para revisão).

Regras que valem para todos:

- só vira incidente IP dentro dos prefixos próprios configurados; IP do
  notificador e de terceiros é descartado;
- porta: só é tratada como porta de **origem** quando o campo diz isso
  explicitamente. ``port`` sozinho é porta de destino/serviço. Nunca se
  deduz porta de texto livre sem um formato explícito reconhecido;
- horário em UTC, guardando o texto original; sem fuso explícito usa o fuso
  configurado para o domínio do remetente e marca ``timezone_assumed``;
- ``new`` só para formato estruturado com IP + porta de origem + horário com
  fuso explícito. O resto é ``review`` com os motivos.
"""

import csv
import html
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from email.header import decode_header, make_header
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:  # PyYAML é opcional: sem ele, lê o formato plano "Chave: valor" e JSON.
    import yaml
except ImportError:  # pragma: no cover - depende do ambiente
    yaml = None

STRUCTURED_PARSERS = ("xarf", "arf", "csv")
INCIDENT_TYPES = (
    "scan",
    "brute-force",
    "ddos",
    "botnet",
    "phishing",
    "spam",
    "copyright",
    "open-service",
    "exploit",
    "other",
)

REASON_FREE_TEXT = "Extraído de texto livre"
REASON_NO_SOURCE_PORT = "Sem porta de origem"
REASON_NO_TIME = "Sem horário do incidente"
REASON_NO_TIMEZONE = "Horário sem fuso e remetente sem fuso configurado"
REASON_TIMEZONE_ASSUMED = "Fuso assumido pelo domínio do remetente"
REASON_BAD_TIME = "Horário em formato não reconhecido"


@dataclass
class ParserSettings:
    own_prefixes: list = field(default_factory=list)
    # domínio do remetente -> fuso IANA (vale também para subdomínios).
    sender_timezones: dict = field(default_factory=dict)

    def __post_init__(self):
        self.networks = [ipaddress.ip_network(p.strip(), strict=False) for p in self.own_prefixes if p.strip()]
        self.sender_timezones = {
            domain.strip().lower().lstrip("."): tz for domain, tz in (self.sender_timezones or {}).items()
        }

    def is_own(self, ip):
        return any(ip.version == net.version and ip in net for net in self.networks)

    def timezone_for(self, domain):
        domain = (domain or "").lower()
        while domain:
            if domain in self.sender_timezones:
                return self.sender_timezones[domain]
            domain = domain.partition(".")[2]
        return None


@dataclass
class IncidentData:
    public_ip: str
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    occurred_at: datetime | None = None
    occurred_at_raw: str | None = None
    timezone_used: str | None = None
    timezone_assumed: bool = False
    incident_type: str = "other"
    raw_type: str | None = None
    status: str = "review"
    review_reasons: list = field(default_factory=list)


@dataclass
class ParseResult:
    parser: str | None
    status: str  # processed | unrecognized
    incidents: list
    message_id: str | None
    sender: str | None
    sender_domain: str | None
    subject: str | None
    received_at: datetime | None
    discarded_ips: int = 0
    notes: list = field(default_factory=list)


# --- entrada --------------------------------------------------------------------

def parse_message(message, settings):
    """Recebe um ``email.message.Message`` e devolve um ``ParseResult``."""
    sender = message_sender(message)
    sender_domain = sender.rpartition("@")[2].lower() if sender and "@" in sender else None
    parser, candidates = None, []
    formats = (("xarf", _parse_xarf), ("arf", _parse_arf), ("csv", _parse_csv), ("text", _parse_text))
    # Cada .eml encaminhado tem seus próprios cabeçalhos e fuso do remetente.
    pending = [(message, 0)]
    while pending:
        envelope, depth = pending.pop(0)
        original_sender = message_sender(envelope) or ""
        context = _Context(settings, original_sender.rpartition("@")[2].lower())
        for name, func in formats:
            found = func(envelope, context)
            if found is not None:
                if parser is None or (found and name in STRUCTURED_PARSERS):
                    parser = name
                candidates.extend((candidate, name) for candidate in found)
                break
        if depth < 10:
            for part in _message_parts(envelope):
                if part.get_content_type() == "message/rfc822":
                    payload = part.get_payload()
                    if isinstance(payload, list):
                        pending.extend((child, depth + 1) for child in payload)

    incidents, discarded, seen = [], 0, set()
    for candidate, candidate_parser in candidates:
        ip = _ip(candidate.public_ip)
        if ip is None or not settings.is_own(ip):
            discarded += 1
            continue
        candidate.public_ip = str(ip)
        key = (
            candidate.public_ip,
            candidate.source_port,
            candidate.destination_ip,
            candidate.destination_port,
            candidate.occurred_at,
            candidate.occurred_at_raw,
        )
        if key in seen:
            continue
        seen.add(key)
        _finalize_status(candidate, candidate_parser)
        incidents.append(candidate)

    # Menção solta do IP no texto ("IP x was banned") não vira incidente à parte
    # quando a mesma notificação já traz porta ou horário para esse IP.
    detailed = {i.public_ip for i in incidents if i.source_port is not None or i.occurred_at_raw}
    incidents = [
        i for i in incidents
        if i.public_ip not in detailed or i.source_port is not None or i.occurred_at_raw
    ]

    notes = []
    if not settings.networks:
        notes.append("Nenhum prefixo próprio configurado")
    return ParseResult(
        parser=parser,
        status="processed" if incidents else "unrecognized",
        incidents=incidents,
        message_id=(message.get("Message-ID") or "").strip() or None,
        sender=sender,
        sender_domain=sender_domain,
        subject=_header(message, "Subject"),
        received_at=header_date(message.get("Date")),
        discarded_ips=discarded,
        notes=notes,
    )


class _Context:
    def __init__(self, settings, sender_domain):
        self.settings = settings
        self.sender_domain = sender_domain
        self.sender_timezone = settings.timezone_for(sender_domain)


def _finalize_status(incident, parser):
    reasons = list(incident.review_reasons)
    if parser not in STRUCTURED_PARSERS:
        reasons.insert(0, REASON_FREE_TEXT)
    if incident.source_port is None:
        reasons.append(REASON_NO_SOURCE_PORT)
    if incident.occurred_at is None and not any(r in reasons for r in (REASON_NO_TIMEZONE, REASON_BAD_TIME)):
        reasons.append(REASON_NO_TIME)
    if incident.timezone_assumed:
        reasons.append(REASON_TIMEZONE_ASSUMED)
    incident.review_reasons = list(dict.fromkeys(reasons))
    incident.status = "review" if incident.review_reasons else "new"


# --- X-ARF ----------------------------------------------------------------------

XARF_KEYS = {
    # "sourceidentifier"/"timestamp"/"type": X-ARF 4.2 (snake_case, ex.: lrob.net).
    "ip": ("source", "sourceip", "srcip", "sourceidentifier"),
    "source_type": ("sourcetype", "sourceidentifiertype"),
    "source_port": ("sourceport", "srcport"),
    "destination_ip": ("destination", "destinationip", "dstip", "target"),
    "destination_port": ("destinationport", "dstport", "port"),
    "time": ("date", "datetime", "attackdate", "timestamp", "time", "starttime", "firstseen"),
    # No 4.2 "category" é a classe ampla ("connection") e "type" o detalhe ("scraping").
    "type": ("reporttype", "type", "category", "feedbacktype"),
}


def _parse_xarf(message, context):
    flag = (message.get("X-ARF") or "").strip().lower()
    if flag in ("", "no", "false", "0"):
        return None
    # Fora do "yes" padrão (ex.: lrob.net manda "PLAIN" + xarf.json), só conta
    # como X-ARF se achar o relatório; senão segue para os outros formatos.
    not_found = [] if flag == "yes" else None
    for part in _leaf_parts(message)[1:] or _leaf_parts(message):
        fields = _structured_fields(_part_text(part))
        if not fields:
            continue
        values = _pick(fields, XARF_KEYS)
        if not values.get("ip"):
            continue
        source_type = (values.get("source_type") or "").lower()
        if source_type and not source_type.startswith("ip"):
            return []
        return [_build(values, context)]
    return not_found


# --- ARF (RFC 5965 / 6692) ------------------------------------------------------

ARF_KEYS = {
    "ip": ("sourceip",),
    "source_port": ("sourceport",),
    "time": ("arrivaldate", "receiveddate"),
    "type": ("feedbacktype",),
}
ARF_TYPES = {"abuse": "spam", "fraud": "phishing", "virus": "botnet"}


def _parse_arf(message, context):
    report = None
    for part in _message_parts(message):
        if part.get_content_type() == "message/feedback-report":
            report = part
            break
    if report is None:
        return None
    fields = _structured_fields(_part_text(report), allow_yaml=False)
    values = _pick(fields, ARF_KEYS)
    if not values.get("ip"):
        return []
    raw_type = values.get("type")
    incident = _build(values, context)
    if raw_type and raw_type.lower() in ARF_TYPES:
        incident.incident_type = ARF_TYPES[raw_type.lower()]
    return [incident]


# --- CSV ------------------------------------------------------------------------

CSV_KEYS = {
    "ip": ("ip", "srcip", "sourceip", "src", "source", "ipaddress", "ipv4", "ipv6"),
    "source_port": ("srcport", "sourceport", "sport"),
    "destination_ip": ("dstip", "destip", "destinationip", "dst", "destination"),
    "destination_port": ("dstport", "destport", "destinationport", "dport", "port"),
    "time": ("timestamp", "datetime", "date", "time", "eventtime", "firstseen"),
    "type": ("type", "category", "infection", "tag", "reporttype", "classification"),
}
SHADOWSERVER_FILE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-([a-z0-9_]+?)(?:-|\.csv$)", re.IGNORECASE)


def _parse_csv(message, context):
    attachments = [part for part in _leaf_parts(message) if _is_csv(part)]
    if not attachments:
        return None
    incidents = []
    for part in attachments:
        text = _part_text(part)
        filename = part.get_filename() or ""
        report_match = SHADOWSERVER_FILE_RE.match(filename)
        try:
            dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(io.StringIO(text), dialect)
        header = next(reader, None)
        if not header:
            continue
        columns = [_norm_key(name) for name in header]
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            fields = {}
            for name, value in zip(columns, row):
                fields.setdefault(name, value.strip())
            values = _pick(fields, CSV_KEYS)
            if report_match:
                # Relatórios do Shadowserver: o nome do relatório (scan_ssh,
                # event4_sinkhole...) descreve melhor que a coluna "tag".
                values["type"] = report_match.group(1)
            if values.get("ip"):
                incidents.append(_build(values, context))
    return incidents


def _is_csv(part):
    filename = (part.get_filename() or "").lower()
    return part.get_content_type() in ("text/csv", "application/csv") or filename.endswith(".csv")


# --- texto livre ----------------------------------------------------------------

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Log com timestamp ISO e porta explicitamente de origem, ligados ao mesmo IP.
SOURCE_LOG_RE = re.compile(
    r"^[\s>]*(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2}))\s+src\s+port\s+(?P<port>\d+)\s+"
    r"(?P<ip>\S+)(?=\s|$)",
    re.IGNORECASE,
)
# Amostra de tcpdump (ex.: NFOservers): "2026-10-17 19:41:07.537924 IP origem.porta >
# destino.porta: ...". Com -v o fluxo vem na linha seguinte, indentado.
TCPDUMP_TIME_RE = re.compile(
    r"^[\s>]*(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2}|\s+UTC)?\s+IP6?\s(?P<rest>.*)$",
    re.IGNORECASE,
)
TCPDUMP_FLOW_RE = re.compile(
    r"(?<![\w.:])(?P<src>[0-9a-f.:]+)\.(?P<sport>\d{1,5})\s+>\s+"
    r"(?P<dst>[0-9a-fx.:]+)\.(?P<dport>\d{1,5}):",  # destino pode vir mascarado (74.91.119.x)
    re.IGNORECASE,
)
# Relatório do SpamCop: "Email from 203.0.113.76 / Mon, 19 Oct 2026 18:08:20 +0000".
# Não traz porta de origem (SMTP); o IP é o que entregou o spam.
SPAMCOP_RE = re.compile(r"^[\s>]*Email from (?P<ip>[0-9a-f.:]+) / (?P<time>\S.*?)\s*$", re.IGNORECASE)
# "The date/timestamps (at the very left) are UTC": vale para as amostras sem fuso.
TIMESTAMPS_UTC_RE = re.compile(r"\b(?:time\s*stamps?|dates?|times?)\b[^\n]{0,80}?\b(?:UTC|GMT)\b", re.IGNORECASE)
# Candidato largo; quem decide é ipaddress (descarta horários "12:30:45", MACs etc.).
IPV6_RE = re.compile(r"(?<![0-9a-f:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:])", re.IGNORECASE)
QUOTED_HEADER_RE = re.compile(
    r"^[\s>]*(received|x-[\w-]+|authentication-results|dkim-signature|arc-[\w-]+|return-path"
    r"|message-id|delivered-to|from|to|cc|reply-to)\s*:",
    re.IGNORECASE,
)
# Indícios de denúncia; endereço abuse@ e mera presença de IP não bastam.
ABUSE_REPORT_RE = re.compile(
    r"\b(?:abuse|spam|attacking|attack|hacking|brute[ -]?force|phishing|malware|"
    r"botnet|ddos|port[ -]?scan|intrusion|denúncia|ataque|invasão)\b", re.IGNORECASE,
)
SNDS_AUTH_SUBJECT_RE = re.compile(
    r"\brequest to authorize\b.*\b(?:hotmail|windows live mail) traffic data\b", re.IGNORECASE,
)


def _parse_text(message, context):
    subject = _header(message, "Subject") or ""
    if SNDS_AUTH_SUBJECT_RE.search(subject):
        return []
    subject_is_report = bool(ABUSE_REPORT_RE.search(subject))
    texts = [part for part in _leaf_parts(message) if part.get_content_type() == "text/plain"]
    if not texts:
        texts = [part for part in _leaf_parts(message) if part.get_content_type() == "text/html"]
    incidents, seen_flows = [], set()
    for part in texts:
        body = _part_text(part)
        if part.get_content_type() == "text/html":
            body = html.unescape(re.sub(r"<[^>]+>", " ", body))
        in_quoted_header = False
        body_utc = bool(TIMESTAMPS_UTC_RE.search(body))
        pending_time, pending_lines = None, 0
        for line in body.splitlines():
            if QUOTED_HEADER_RE.match(line):
                in_quoted_header = True
                continue
            if in_quoted_header and line[:1] in (" ", "\t"):
                continue  # continuação de cabeçalho citado (ex.: Received em várias linhas)
            in_quoted_header = False
            packet = TCPDUMP_TIME_RE.match(line)
            if packet:
                tz = (packet["tz"] or "").strip()
                if tz.upper() in ("UTC", "Z") or (not tz and body_utc):
                    tz = "+00:00"
                pending_time = packet["time"] + tz
                line = packet["rest"]
            flow = TCPDUMP_FLOW_RE.search(line) if pending_time else None
            if flow and _ip(flow["src"]) is not None:
                # Vários pacotes do mesmo fluxo = mesma sessão; fica o primeiro.
                if flow.group("src", "sport", "dst", "dport") in seen_flows:
                    pending_time = None
                    continue
                seen_flows.add(flow.group("src", "sport", "dst", "dport"))
                incidents.append(_build({
                    "ip": flow["src"], "source_port": flow["sport"],
                    "destination_ip": flow["dst"], "destination_port": flow["dport"],
                    "time": pending_time,
                }, context))
                pending_time = None
                continue
            if packet:
                pending_lines = 3
                continue  # fluxo deve vir na próxima linha (tcpdump -v)
            if pending_time:
                # Cliente de e-mail pode quebrar o cabeçalho do pacote em mais linhas.
                pending_lines -= 1
                if pending_lines <= 0 or not line.strip(" >\t"):
                    pending_time = None
            log = SOURCE_LOG_RE.match(line)
            if log and _ip(log["ip"]) is not None:
                incidents.append(_build({
                    "ip": log["ip"], "source_port": log["port"], "time": log["time"],
                }, context))
                continue
            spamcop = SPAMCOP_RE.match(line)
            if spamcop and _ip(spamcop["ip"]) is not None:
                incidents.append(_build({"ip": spamcop["ip"], "time": spamcop["time"], "type": "spam"}, context))
                continue
            if not subject_is_report and not ABUSE_REPORT_RE.search(line):
                continue
            for match in list(IPV4_RE.finditer(line)) + list(IPV6_RE.finditer(line)):
                if _ip(match.group(0)) is not None:
                    incidents.append(IncidentData(public_ip=match.group(0)))
    return incidents


# --- montagem do incidente --------------------------------------------------------

def _build(values, context):
    incident = IncidentData(
        public_ip=values["ip"],
        source_port=_port(values.get("source_port")),
        destination_ip=_valid_ip_text(values.get("destination_ip")),
        destination_port=_port(values.get("destination_port")),
        raw_type=(values.get("type") or None),
    )
    incident.incident_type = classify_type(incident.raw_type)
    raw_time = values.get("time")
    if raw_time:
        incident.occurred_at_raw = raw_time[:120]
        _apply_time(incident, raw_time, context)
    return incident


def _apply_time(incident, raw, context):
    parsed, explicit = parse_time(raw)
    if parsed is None:
        incident.review_reasons.append(REASON_BAD_TIME)
        return
    if explicit:
        offset = parsed.utcoffset()
        incident.timezone_used = "UTC" if not offset else parsed.strftime("UTC%z")
        incident.occurred_at = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return
    if not context.sender_timezone:
        incident.review_reasons.append(REASON_NO_TIMEZONE)
        return
    try:
        zone = ZoneInfo(context.sender_timezone)
    except (ZoneInfoNotFoundError, ValueError):
        incident.review_reasons.append(REASON_NO_TIMEZONE)
        return
    incident.timezone_used = context.sender_timezone
    incident.timezone_assumed = True
    incident.occurred_at = parsed.replace(tzinfo=zone).astimezone(timezone.utc).replace(tzinfo=None)


TZ_SUFFIX_RE = re.compile(r"\s*(?:UTC|GMT|Z)$", re.IGNORECASE)
TZ_OFFSET_RE = re.compile(r"\s*([+-]\d{2}):?(\d{2})$")


def parse_time(raw):
    """Texto -> (datetime, fuso_explícito). Datetime sem fuso quando não informado."""
    text = (raw or "").strip()
    if not text:
        return None, False
    if re.fullmatch(r"\d{9,10}(?:\.\d+)?", text):
        return datetime.fromtimestamp(float(text), tz=timezone.utc), True

    iso = TZ_SUFFIX_RE.sub("+00:00", text)
    iso = TZ_OFFSET_RE.sub(r"\1:\2", iso)
    try:
        value = datetime.fromisoformat(iso)
        return value, value.tzinfo is not None
    except ValueError:
        pass
    try:
        value = parsedate_to_datetime(text)
        if value is not None:
            # RFC 5322: "-0000" significa fuso desconhecido e vem sem tzinfo.
            return value, value.tzinfo is not None
    except (TypeError, ValueError, IndexError):
        pass
    for pattern in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            return datetime.strptime(TZ_OFFSET_RE.sub("", text), pattern), False
        except ValueError:
            continue
    return None, False


TYPE_RULES = (
    ("copyright", ("copyright", "dmca", "infring", "piracy")),
    ("phishing", ("phish",)),
    ("spam", ("spam", "uce", "ube")),
    ("ddos", ("ddos", "dos", "flood")),
    ("botnet", ("botnet", "bot", "c2", "cnc", "sinkhole", "drone", "infect", "malware")),
    ("brute-force", ("brute", "login", "password", "credential", "auth")),
    ("exploit", ("exploit", "intrusion", "injection", "vuln", "attack", "hack")),
    ("open-service", ("open", "exposed", "accessible", "amplif")),
    ("scan", ("scan", "probe")),
)


def classify_type(raw):
    if not raw:
        return "other"
    value = raw.strip().lower()
    if value.replace("_", "-") in INCIDENT_TYPES:
        return value.replace("_", "-")
    if value.startswith("scan_"):
        # Convenção do Shadowserver: scan_<serviço> = serviço exposto, não varredura.
        return "open-service"
    tokens = set(re.split(r"[^a-z0-9]+", value)) - {""}
    for incident_type, words in TYPE_RULES:
        for word in words:
            if word in tokens or (len(word) > 3 and word in value):
                return incident_type
    return "other"


# --- exibição ----------------------------------------------------------------------

def message_text(message, limit=200_000):
    """Texto legível do e-mail (partes text/plain; sem elas, HTML sem tags).

    Para exibir ao operador em <pre>: nunca renderizar o HTML original.
    """
    leaves = [part for part in message.walk() if not part.is_multipart()]
    plain = [part for part in leaves if part.get_content_type() == "text/plain" and not part.get_filename()]
    if plain:
        text = "\n\n".join(_part_text(part) for part in plain)
    else:
        html_parts = [part for part in leaves if part.get_content_type() == "text/html"]
        text = "\n\n".join(html.unescape(re.sub(r"<[^>]+>", " ", _part_text(part))) for part in html_parts)
    return text[:limit]


def message_attachments(message):
    items = []
    for part in _leaf_parts(message):
        filename = part.get_filename()
        if not filename and part.get_content_maintype() not in ("application",):
            continue
        payload = part.get_payload(decode=True) or b""
        items.append({"filename": filename, "content_type": part.get_content_type(), "size": len(payload)})
    return items


# --- utilitários ----------------------------------------------------------------

def _norm_key(name):
    return re.sub(r"[\s_\-.]+", "", (name or "").strip().lower())


def _pick(fields, key_map):
    values = {}
    for target, names in key_map.items():
        for name in names:
            value = fields.get(name)
            if value not in (None, ""):
                values[target] = str(value).strip()
                break
    return values


def _structured_fields(text, allow_yaml=True):
    text = (text or "").strip()
    if not text:
        return {}
    data = None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    if data is None and allow_yaml and yaml is not None:
        try:
            # BaseLoader mantém tudo como texto: "Date:" não vira datetime e o
            # horário original é guardado exatamente como veio.
            data = yaml.load(text, Loader=yaml.BaseLoader)
        except yaml.YAMLError:
            data = None
    if isinstance(data, dict):
        return _flatten(data)
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() and not key.startswith((" ", "\t")):
            fields.setdefault(_norm_key(key), value.strip().strip("'\""))
    return fields


def _flatten(data, out=None):
    out = {} if out is None else out
    for key, value in data.items():
        if isinstance(value, dict):
            _flatten(value, out)
        elif not isinstance(value, list):
            out.setdefault(_norm_key(str(key)), "" if value is None else str(value))
    return out


def _message_parts(message):
    """Partes do envelope atual, sem misturar anexos message/rfc822."""
    yield message
    if message.get_content_type() != "message/rfc822" and message.is_multipart():
        for child in message.get_payload():
            yield from _message_parts(child)


def _leaf_parts(message):
    return [part for part in _message_parts(message) if not part.is_multipart()]


def _part_text(part):
    payload = part.get_payload()
    if isinstance(payload, list):
        # message/feedback-report e afins chegam como lista de blocos de cabeçalho.
        return "\n".join(
            "\n".join(f"{key}: {value}" for key, value in block.items()) for block in payload
        )
    data = part.get_payload(decode=True)
    if data is None:
        return payload if isinstance(payload, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def message_sender(message):
    for name, address in getaddresses([message.get("From", "")]):
        if address:
            return address.strip()
    return parseaddr(message.get("Sender", ""))[1] or None


def _header(message, name):
    value = message.get(name)
    if value is None:
        return None
    try:
        return str(make_header(decode_header(str(value)))).strip()
    except (LookupError, UnicodeError):
        return str(value).strip()


def header_date(value):
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(str(value))
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _ip(text):
    try:
        return ipaddress.ip_address((text or "").strip().strip("[]"))
    except ValueError:
        return None


def _valid_ip_text(text):
    ip = _ip(text)
    return str(ip) if ip is not None else None


def _port(value):
    if value in (None, ""):
        return None
    try:
        port = int(str(value).strip())
    except ValueError:
        return None
    return port if 0 < port <= 65535 else None
