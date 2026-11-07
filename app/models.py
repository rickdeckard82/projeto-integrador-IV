from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    session_token = db.Column(db.String(64), nullable=True)
    api_token_hash = db.Column(db.String(64), unique=True, nullable=True)
    # Acesso ao módulo de abuse (dados pessoais: IP + porta + horário + assinante).
    abuse_access = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class UploadBatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    office_number = db.Column(db.String(120), index=True, nullable=False)
    process_number = db.Column(db.String(25), index=True, nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    sei_numbers = db.Column(db.Text, nullable=True)
    office_key = db.Column(db.String(160), index=True, nullable=True)
    expedition_date = db.Column(db.Date, nullable=True)
    removal_date = db.Column(db.Date, nullable=True)
    # Preenchido quando o comunicado deste ofício é enviado (ou marcado como enviado).
    notification_sent_at = db.Column(db.DateTime, nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    total_found = db.Column(db.Integer, default=0, nullable=False)
    new_count = db.Column(db.Integer, default=0, nullable=False)
    existing_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class OfficeFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    office_id = db.Column(db.Integer, db.ForeignKey("upload_batch.id"), nullable=False)
    file_type = db.Column(db.String(30), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(120), nullable=True)
    removal_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class OfficeDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    office_id = db.Column(db.Integer, db.ForeignKey("upload_batch.id"), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey("domain.id"), nullable=False)
    original_value = db.Column(db.String(500), nullable=True)
    removal_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("office_id", "domain_id", name="uq_office_domain"),)


class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(253), unique=True, index=True, nullable=False)
    first_seen_batch_id = db.Column(db.Integer, db.ForeignKey("upload_batch.id"), nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)
    redirect_target = db.Column(db.String(253), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class Deployment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deployment_type = db.Column(db.String(30), default="rpz", nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    status = db.Column(db.String(30), nullable=False)
    domain_count = db.Column(db.Integer, nullable=False)
    ip_count = db.Column(db.Integer, default=0, nullable=False)
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class PublicationLock(db.Model):
    name = db.Column(db.String(80), primary_key=True)
    owner = db.Column(db.String(120), nullable=True)
    acquired_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class CompanySettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(160), nullable=True)
    cnpj = db.Column(db.String(30), nullable=True)
    asn = db.Column(db.String(30), nullable=True)
    address = db.Column(db.Text, nullable=True)
    address_street = db.Column(db.String(180), nullable=True)
    address_number = db.Column(db.String(30), nullable=True)
    address_complement = db.Column(db.String(120), nullable=True)
    address_neighborhood = db.Column(db.String(120), nullable=True)
    address_city = db.Column(db.String(120), nullable=True)
    address_state = db.Column(db.String(2), nullable=True)
    address_zip = db.Column(db.String(20), nullable=True)
    anatel_responsible_name = db.Column(db.String(160), nullable=True)
    anatel_responsible_phone = db.Column(db.String(60), nullable=True)
    anatel_responsible_email = db.Column(db.String(160), nullable=True)
    duty_phone = db.Column(db.String(60), nullable=True)
    duty_email = db.Column(db.String(160), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class ParameterSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dns_primary = db.Column(db.String(160), nullable=True)
    dns_secondary = db.Column(db.String(160), nullable=True)
    extra_dns_servers = db.Column(db.Text, nullable=True)
    # Listas JSON de alvos SSH com credenciais (ver app/ssh_settings.py).
    publish_routers = db.Column(db.Text, nullable=True)
    router_command_ipv4 = db.Column(db.Text, nullable=True)
    router_command_ipv6 = db.Column(db.Text, nullable=True)
    # NULL = nunca salvo; enquanto isso a configuração antiga do .env é importada.
    rpz_servers = db.Column(db.Text, nullable=True)
    # Servidor de nomes do SOA/NS da zona RPZ; vazio = localhost.
    rpz_nameserver = db.Column(db.String(253), nullable=True)
    # NULL = padrão (verificar).
    ssh_strict_host_key_checking = db.Column(db.Boolean, nullable=True)
    # SMTP para o envio de comunicados; security: "starttls", "ssl" ou "none".
    smtp_host = db.Column(db.String(253), nullable=True)
    smtp_port = db.Column(db.Integer, nullable=True)
    smtp_security = db.Column(db.String(10), nullable=True)
    smtp_user = db.Column(db.String(255), nullable=True)
    # Nunca devolvida pela API; vazio no formulário mantém a atual.
    smtp_password = db.Column(db.String(255), nullable=True)
    smtp_from_email = db.Column(db.String(255), nullable=True)
    smtp_from_name = db.Column(db.String(160), nullable=True)
    email_signature = db.Column(db.Text, nullable=True)
    # Caixa de abuse (IMAPS, somente leitura). NULL em imap_host = nunca salvo; enquanto
    # isso a configuração antiga do .env é importada.
    imap_host = db.Column(db.String(253), nullable=True)
    imap_port = db.Column(db.Integer, nullable=True)
    imap_user = db.Column(db.String(255), nullable=True)
    # Nunca devolvida pela API; vazio no formulário mantém a atual.
    imap_password = db.Column(db.String(255), nullable=True)
    imap_mailbox = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class SentEmail(db.Model):
    """Histórico dos comunicados enviados por e-mail (inclusive as tentativas com falha)."""

    id = db.Column(db.Integer, primary_key=True)
    office_id = db.Column(db.Integer, db.ForeignKey("upload_batch.id"), index=True, nullable=True)
    # Número do ofício como estava no envio (o ofício pode ser removido depois).
    office_number = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    recipients = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(500), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # Nomes dos anexos, separados por quebra de linha (o conteúdo não é guardado).
    attachments = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(10), nullable=False)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)


class BackupSchedule(db.Model):
    """Backup automático por FTP (uma linha só). Executado pelo backup-worker."""

    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    # Horário diário "HH:MM" no fuso BACKUP_TIMEZONE.
    run_time = db.Column(db.String(5), default="02:30", nullable=False)
    include_database = db.Column(db.Boolean, default=True, nullable=False)
    include_files = db.Column(db.Boolean, default=True, nullable=False)
    keep_count = db.Column(db.Integer, default=7, nullable=False)
    ftp_host = db.Column(db.String(255), nullable=True)
    ftp_port = db.Column(db.Integer, default=21, nullable=False)
    ftp_user = db.Column(db.String(255), nullable=True)
    # Nunca devolvida pela API; vazio no formulário mantém a atual.
    ftp_password = db.Column(db.String(255), nullable=True)
    ftp_directory = db.Column(db.String(500), nullable=True)
    ftp_tls = db.Column(db.Boolean, default=True, nullable=False)
    # Destino só de gravação (ex.: Pulse Backup): envia direto com o nome final e não
    # apaga cópias antigas (a retenção fica a cargo do servidor de backup).
    ftp_write_only = db.Column(db.Boolean, default=False, nullable=False)
    run_requested_at = db.Column(db.DateTime, nullable=True)
    last_attempt_at = db.Column(db.DateTime, nullable=True)
    last_success_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(20), nullable=True)
    last_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class IpBatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    office_id = db.Column(db.Integer, db.ForeignKey("upload_batch.id"), nullable=False)
    name = db.Column(db.String(160), index=True, nullable=False)
    office_key = db.Column(db.String(160), index=True, nullable=True)
    expedition_date = db.Column(db.Date, nullable=True)
    removal_date = db.Column(db.Date, nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    total_found = db.Column(db.Integer, default=0, nullable=False)
    new_count = db.Column(db.Integer, default=0, nullable=False)
    existing_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class IpBatchFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey("ip_batch.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class IpAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(64), unique=True, index=True, nullable=False)
    version = db.Column(db.Integer, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class WhitelistDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(253), unique=True, index=True, nullable=False)
    reason = db.Column(db.Text, nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class WhitelistIp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(64), unique=True, index=True, nullable=False)
    reason = db.Column(db.Text, nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class IpWhoisCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey("ip_address.id"), unique=True, nullable=False)
    asn = db.Column(db.Integer, nullable=True)
    as_name = db.Column(db.String(255), nullable=True)
    bgp_prefix = db.Column(db.String(80), nullable=True)
    registry = db.Column(db.String(40), nullable=True)
    country = db.Column(db.String(8), nullable=True)
    rdap_name = db.Column(db.String(255), nullable=True)
    rdap_handle = db.Column(db.String(120), nullable=True)
    rdap_country = db.Column(db.String(8), nullable=True)
    error = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class IpWhoisJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey("ip_address.id"), unique=True, nullable=False)
    status = db.Column(db.String(20), default="pending", index=True, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    error = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)


class IpBatchAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey("ip_batch.id"), nullable=False)
    ip_id = db.Column(db.Integer, db.ForeignKey("ip_address.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("batch_id", "ip_id", name="uq_ip_batch_address"),)


class CgnatRule(db.Model):
    """Regra do CGNAT determinístico, versionada por vigência (pools mudam)."""

    id = db.Column(db.Integer, primary_key=True)
    private_prefix = db.Column(db.String(64), nullable=False)
    public_prefix = db.Column(db.String(64), nullable=False)
    ports_per_subscriber = db.Column(db.Integer, nullable=False)
    first_port = db.Column(db.Integer, nullable=False)
    # "interleaved" (A10 use-all-nat-ips) ou "sequential"; ver app/cgnat.py.
    allocation = db.Column(db.String(20), nullable=False)
    # Vigência em UTC: valid_from <= instante < valid_to (nulo = vigente).
    valid_from = db.Column(db.DateTime, nullable=False, index=True)
    valid_to = db.Column(db.DateTime, nullable=True)
    pool_name = db.Column(db.String(120), nullable=True)
    # Regras importadas juntas (vários arquivos, mesma vigência) compartilham o grupo.
    import_group = db.Column(db.String(36), nullable=True, index=True)
    # Importação que encerrou esta regra (valid_to); apagar aquela importação reabre esta.
    closed_by_group = db.Column(db.String(36), nullable=True, index=True)
    source_filename = db.Column(db.String(255), nullable=True)
    source_md5 = db.Column(db.String(32), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class AbuseMailboxState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mailbox = db.Column(db.String(255), unique=True, nullable=False)
    uidvalidity = db.Column(db.BigInteger, nullable=True)
    last_uid = db.Column(db.BigInteger, default=0, nullable=False)
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class AbuseMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Text, nullable=True)
    # sha256 do Message-ID (ou do conteúdo bruto, quando não houver Message-ID).
    message_key = db.Column(db.String(64), unique=True, nullable=False)
    imap_uidvalidity = db.Column(db.BigInteger, nullable=True)
    imap_uid = db.Column(db.BigInteger, nullable=True)
    sender = db.Column(db.String(320), nullable=True)
    sender_domain = db.Column(db.String(253), index=True, nullable=True)
    subject = db.Column(db.Text, nullable=True)
    received_at = db.Column(db.DateTime, index=True, nullable=True)
    raw_path = db.Column(db.String(500), nullable=True)
    raw_sha256 = db.Column(db.String(64), nullable=True)
    raw_size = db.Column(db.Integer, nullable=True)
    raw_purged_at = db.Column(db.DateTime, nullable=True)
    parser = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), default="processed", index=True, nullable=False)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("imap_uidvalidity", "imap_uid", name="uq_abuse_message_imap_uid"),
    )


class AbuseIncident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    abuse_message_id = db.Column(
        db.Integer, db.ForeignKey("abuse_message.id"), index=True, nullable=False
    )
    public_ip = db.Column(db.String(64), index=True, nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_ip = db.Column(db.String(64), nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    # Sempre em UTC (naive, como no resto do sistema). Nulo quando não informado.
    occurred_at = db.Column(db.DateTime, index=True, nullable=True)
    occurred_at_raw = db.Column(db.String(120), nullable=True)
    timezone_used = db.Column(db.String(64), nullable=True)
    timezone_assumed = db.Column(db.Boolean, default=False, nullable=False)
    incident_type = db.Column(db.String(20), default="other", index=True, nullable=False)
    raw_type = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(20), default="review", index=True, nullable=False)
    review_reasons = db.Column(db.Text, nullable=True)
    private_ip = db.Column(db.String(64), index=True, nullable=True)
    cgnat_rule_id = db.Column(db.Integer, db.ForeignKey("cgnat_rule.id"), nullable=True)
    pppoe_login = db.Column(db.String(120), index=True, nullable=True)
    hubsoft_customer_code = db.Column(db.String(60), index=True, nullable=True)
    action_taken = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    identified_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    identified_at = db.Column(db.DateTime, nullable=True)
    handled_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    handled_at = db.Column(db.DateTime, nullable=True)
    # Preenchido pela retenção: vínculo com o assinante e porta removidos.
    anonymized_at = db.Column(db.DateTime, index=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class AbuseAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=True)
    incident_id = db.Column(
        db.Integer, db.ForeignKey("abuse_incident.id"), index=True, nullable=True
    )
    abuse_message_id = db.Column(
        db.Integer, db.ForeignKey("abuse_message.id"), index=True, nullable=True
    )
    action = db.Column(db.String(30), nullable=False)
    details = db.Column(db.Text, nullable=True)
    remote_addr = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)


class AbuseSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Listas/mapas em JSON, como ParameterSettings.
    own_prefixes = db.Column(db.Text, nullable=True)
    sender_timezones = db.Column(db.Text, nullable=True)
    lookup_window_minutes = db.Column(db.Integer, default=5, nullable=False)
    recurrence_days = db.Column(db.Integer, default=30, nullable=False)
    # Dias após o tratamento (ou após o recebimento, sem incidentes) para apagar o .eml.
    raw_retention_days = db.Column(db.Integer, default=30, nullable=True)
    # Dias após "Tratado" para anonimizar o incidente. Nulo = nunca.
    incident_anonymize_days = db.Column(db.Integer, default=30, nullable=True)
    last_retention_run_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
