import json
import re
from datetime import date, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from threading import Thread
from uuid import uuid4

from flask import current_app, send_file, session
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.utils import secure_filename

from .extractors import ip_sort_key, normalize_domain, normalize_ip_address, remove_email_addresses
from .models import (
    CompanySettings,
    Deployment,
    Domain,
    IpAddress,
    IpBatch,
    IpBatchAddress,
    IpBatchFile,
    IpWhoisCache,
    IpWhoisJob,
    OfficeDomain,
    OfficeFile,
    ParameterSettings,
    PublicationLock,
    SentEmail,
    UploadBatch,
    User,
    WhitelistDomain,
    WhitelistIp,
    db,
)
from .ssh_publish import publish_ip_routes
from .ssh_settings import load_targets
from .whois_jobs import enqueue_ip_whois_jobs

ALLOWED_EXTENSIONS = {".pdf", ".ods", ".xls", ".xlsx", ".xlsm"}
IP_ALLOWED_EXTENSIONS = {".pdf", ".xls", ".xlsx", ".xlsm"}
INTIMATION_EXTENSIONS = {".pdf", ".html", ".htm"}
QUERY_CHUNK_SIZE = 500
BULK_INSERT_CHUNK_SIZE = 1000
PROCESS_NUMBER_PATTERN = re.compile(r"^\d{5}\.\d{6}/\d{4}-\d{2}$")
PUBLISH_LOCK_NAME = "ssh_publish"

DEFAULT_ROUTER_COMMAND_IPV4 = "set routing-instances BLOQUEADOS routing-options static route {address} discard"
DEFAULT_ROUTER_COMMAND_IPV6 = (
    "set routing-instances BLOQUEADOS routing-options rib BLOQUEADOS.inet6.0 static route {address} discard"
)


def start_router_deployment(deployment_id, route_config, log_message, lock_name=None, routers=None):
    app = current_app._get_current_object()

    def worker():
        with app.app_context():
            deployment = Deployment.query.get(deployment_id)
            if not deployment:
                if lock_name:
                    release_publish_lock(lock_name)
                return
            try:
                deployment.message = publish_ip_routes(
                    route_config, routers, configured_strict_host_key_checking()
                )
                deployment.status = "success"
            except Exception as exc:
                current_app.logger.exception(log_message)
                deployment.status = "error"
                deployment.message = str(exc)
            finally:
                db.session.commit()
                if lock_name:
                    release_publish_lock(lock_name)
                db.session.remove()

    Thread(target=worker, daemon=True).start()


def acquire_publish_lock(lock_name=PUBLISH_LOCK_NAME, owner=None):
    now = datetime.utcnow()
    timeout = timedelta(minutes=current_app.config["PUBLISH_LOCK_TIMEOUT_MINUTES"])
    lock = PublicationLock.query.get(lock_name)
    if lock and now - lock.acquired_at > timeout:
        db.session.delete(lock)
        db.session.commit()
        lock = None
    if lock:
        return False

    owner = owner or session.get("username") or f"usuario-{session.get('user_id')}"
    db.session.add(PublicationLock(name=lock_name, owner=owner, acquired_at=now))
    try:
        db.session.commit()
        return True
    except IntegrityError:
        db.session.rollback()
        return False


def release_publish_lock(lock_name=PUBLISH_LOCK_NAME):
    lock = PublicationLock.query.get(lock_name)
    if lock:
        db.session.delete(lock)
        db.session.commit()


def load_json_list(value):
    if not value:
        return []
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [str(item) for item in loaded if str(item).strip()]


def build_communication_config(company, parameters):
    company = company or CompanySettings()
    parameters = parameters or ParameterSettings()
    publish_routers = load_targets(parameters.publish_routers, "router")
    return {
        "dnsServers": [
            value
            for value in [parameters.dns_primary, parameters.dns_secondary]
            if value
        ],
        "borderRouter": publish_routers[0]["name"] if publish_routers else "",
        "contactName": company.anatel_responsible_name or "",
        "contactPhone": company.anatel_responsible_phone or "",
        "dutyPhone": company.duty_phone or "",
        "dutyEmail": company.duty_email or "",
        "companyName": company.company_name or "",
        "companyAddressLines": company_address_lines(company),
        "smtpConfigured": bool(parameters.smtp_host and parameters.smtp_from_email),
        "emailSignature": parameters.email_signature or "",
    }


def company_address_lines(company):
    if not company:
        return []

    street_line = " ".join(
        part
        for part in [
            company.address_street,
            company.address_number,
            company.address_complement,
            company.address_neighborhood,
        ]
        if part
    )
    city_line = "-".join(part for part in [company.address_city, company.address_state] if part)
    lines = [line for line in [street_line, city_line, company.address_zip] if line]
    if not lines and company.address:
        return [line.strip() for line in company.address.splitlines() if line.strip()]
    return lines


def _toggle_office_items_by_recency(office, item_ids, count_active, activate, deactivate, load_other_dates_by_item):
    """Reativa os itens do ofício se todos estiverem inativos; senão desativa só os que não
    aparecem em outro ofício com expedição igual ou mais recente (preservando os compartilhados)."""
    if not item_ids:
        return None

    if count_active(item_ids) == 0:
        updated = activate(item_ids)
        db.session.commit()
        return {"action": "activated", "updated": updated, "preserved": 0}

    other_dates_by_item = load_other_dates_by_item(item_ids)

    def office_is_most_recent(item_id):
        other_dates = other_dates_by_item.get(item_id)
        if not other_dates:
            return True
        if office.expedition_date is None:
            return False
        return all(office.expedition_date >= (other or date.min) for other in other_dates)

    shared_ids = set(other_dates_by_item.keys())
    deactivatable_ids = [item_id for item_id in item_ids if office_is_most_recent(item_id)]
    preserved_count = len(item_ids) - len(deactivatable_ids)
    if not deactivatable_ids:
        return {"action": "none", "updated": 0, "preserved": len(shared_ids)}

    updated = deactivate(deactivatable_ids)
    db.session.commit()
    return {"action": "deactivated", "updated": updated, "preserved": preserved_count}


def perform_office_domain_toggle(office):
    domain_ids = [
        row.domain_id
        for row in OfficeDomain.query.filter_by(office_id=office.id)
        .with_entities(OfficeDomain.domain_id)
        .all()
    ]

    def load_other_dates_by_domain(domain_ids):
        rows = (
            db.session.query(OfficeDomain.domain_id, UploadBatch.expedition_date)
            .join(UploadBatch, UploadBatch.id == OfficeDomain.office_id)
            .filter(OfficeDomain.domain_id.in_(domain_ids), OfficeDomain.office_id != office.id)
            .all()
        )
        other_dates = {}
        for domain_id, expedition_date in rows:
            other_dates.setdefault(domain_id, []).append(expedition_date)
        return other_dates

    return _toggle_office_items_by_recency(
        office,
        domain_ids,
        count_active=lambda ids: Domain.query.filter(Domain.id.in_(ids), Domain.active.is_(True)).count(),
        activate=lambda ids: Domain.query.filter(Domain.id.in_(ids), Domain.active.is_(False)).update(
            {Domain.active: True}, synchronize_session=False
        ),
        deactivate=lambda ids: Domain.query.filter(Domain.id.in_(ids), Domain.active.is_(True)).update(
            {Domain.active: False}, synchronize_session=False
        ),
        load_other_dates_by_item=load_other_dates_by_domain,
    )


def perform_office_ip_toggle(office):
    batch_ids = [batch.id for batch in ip_batches_query_for_office(office).all()]
    if not batch_ids:
        return None

    ip_ids = [
        row.ip_id
        for row in IpBatchAddress.query.filter(IpBatchAddress.batch_id.in_(batch_ids))
        .with_entities(IpBatchAddress.ip_id)
        .distinct()
        .all()
    ]
    if not ip_ids:
        return {"no_ips": True}

    def load_other_dates_by_ip(ip_ids):
        rows = (
            db.session.query(IpBatchAddress.ip_id, UploadBatch.expedition_date)
            .join(IpBatch, IpBatch.id == IpBatchAddress.batch_id)
            .join(UploadBatch, UploadBatch.id == IpBatch.office_id)
            .filter(IpBatchAddress.ip_id.in_(ip_ids), ~IpBatchAddress.batch_id.in_(batch_ids))
            .all()
        )
        other_dates = {}
        for ip_id, expedition_date in rows:
            other_dates.setdefault(ip_id, []).append(expedition_date)
        return other_dates

    return _toggle_office_items_by_recency(
        office,
        ip_ids,
        count_active=lambda ids: IpAddress.query.filter(IpAddress.id.in_(ids), IpAddress.active.is_(True)).count(),
        activate=lambda ids: IpAddress.query.filter(IpAddress.id.in_(ids), IpAddress.active.is_(False)).update(
            {IpAddress.active: True}, synchronize_session=False
        ),
        deactivate=lambda ids: IpAddress.query.filter(IpAddress.id.in_(ids), IpAddress.active.is_(True)).update(
            {IpAddress.active: False}, synchronize_session=False
        ),
        load_other_dates_by_item=load_other_dates_by_ip,
    )


def perform_office_deletion(office):
    domain_ids = [
        row.domain_id
        for row in OfficeDomain.query.filter_by(office_id=office.id)
        .with_entities(OfficeDomain.domain_id)
        .all()
    ]
    shared_domain_ids = set()
    if domain_ids:
        shared_domain_ids = {
            row.domain_id
            for row in OfficeDomain.query.filter(
                OfficeDomain.domain_id.in_(domain_ids),
                OfficeDomain.office_id != office.id,
            )
            .with_entities(OfficeDomain.domain_id)
            .distinct()
            .all()
        }
    exclusive_domain_ids = [domain_id for domain_id in domain_ids if domain_id not in shared_domain_ids]
    files = OfficeFile.query.filter_by(office_id=office.id).all()
    stored_filenames = {file.stored_filename for file in files}
    if office.stored_filename and not office.stored_filename.startswith("manual-"):
        stored_filenames.add(office.stored_filename)
    ip_batches = IpBatch.query.filter_by(office_id=office.id).all()
    ip_batch_ids = [batch.id for batch in ip_batches]
    ip_ids = []
    shared_ip_ids = set()
    exclusive_ip_ids = []
    if ip_batch_ids:
        ip_ids = [
            row.ip_id
            for row in IpBatchAddress.query.filter(IpBatchAddress.batch_id.in_(ip_batch_ids))
            .with_entities(IpBatchAddress.ip_id)
            .distinct()
            .all()
        ]
        if ip_ids:
            shared_ip_ids = {
                row.ip_id
                for row in IpBatchAddress.query.filter(
                    IpBatchAddress.ip_id.in_(ip_ids),
                    ~IpBatchAddress.batch_id.in_(ip_batch_ids),
                )
                .with_entities(IpBatchAddress.ip_id)
                .distinct()
                .all()
            }
            exclusive_ip_ids = [ip_id for ip_id in ip_ids if ip_id not in shared_ip_ids]
        ip_files = IpBatchFile.query.filter(IpBatchFile.batch_id.in_(ip_batch_ids)).all()
        stored_filenames.update(file.stored_filename for file in ip_files)

    try:
        if shared_domain_ids:
            Domain.query.filter(
                Domain.id.in_(shared_domain_ids),
                Domain.first_seen_batch_id == office.id,
            ).update({Domain.first_seen_batch_id: None}, synchronize_session=False)

        # O histórico de e-mails enviados é mantido (guarda o número do ofício).
        SentEmail.query.filter_by(office_id=office.id).update(
            {SentEmail.office_id: None}, synchronize_session=False
        )
        OfficeDomain.query.filter_by(office_id=office.id).delete(synchronize_session=False)
        OfficeFile.query.filter_by(office_id=office.id).delete(synchronize_session=False)
        if ip_batch_ids:
            IpBatchAddress.query.filter(IpBatchAddress.batch_id.in_(ip_batch_ids)).delete(
                synchronize_session=False
            )
            IpBatchFile.query.filter(IpBatchFile.batch_id.in_(ip_batch_ids)).delete(
                synchronize_session=False
            )
            IpBatch.query.filter(IpBatch.id.in_(ip_batch_ids)).delete(synchronize_session=False)

        if exclusive_domain_ids:
            Domain.query.filter(Domain.id.in_(exclusive_domain_ids)).delete(
                synchronize_session=False
            )
        if exclusive_ip_ids:
            IpWhoisJob.query.filter(IpWhoisJob.ip_id.in_(exclusive_ip_ids)).delete(
                synchronize_session=False
            )
            IpWhoisCache.query.filter(IpWhoisCache.ip_id.in_(exclusive_ip_ids)).delete(
                synchronize_session=False
            )
            IpAddress.query.filter(IpAddress.id.in_(exclusive_ip_ids)).delete(
                synchronize_session=False
            )

        db.session.delete(office)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        raise

    delete_stored_files(stored_filenames)
    return {
        "exclusive_domain_count": len(exclusive_domain_ids),
        "exclusive_ip_count": len(exclusive_ip_ids),
        "shared_domain_count": len(shared_domain_ids),
        "shared_ip_count": len(shared_ip_ids),
    }


def parse_date(value):
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d").date()


def parse_manual_domains(value):
    domains = {
        normalize_domain(line)
        for line in remove_email_addresses(value).splitlines()
        if line.strip()
    }
    return sorted(domain for domain in domains if domain)


def parse_manual_ips(value):
    addresses = {
        normalize_ip_address(line)
        for line in re.split(r"[\s,;]+", value or "")
        if line.strip()
    }
    return sorted((address for address in addresses if address), key=ip_config_sort_key)


def normalize_sei_numbers(value):
    numbers = [number.strip() for number in (value or "").split(",") if number.strip()]
    return ", ".join(numbers)


def save_ip_batch(batch, found_ips, batch_files=None):
    db.session.add(batch)
    db.session.flush()

    for batch_file in batch_files or []:
        db.session.add(
            IpBatchFile(
                batch_id=batch.id,
                filename=batch_file["filename"],
                stored_filename=batch_file["stored_filename"],
                content_type=batch_file.get("content_type"),
            )
        )

    existing_addresses = set(load_ip_ids_by_address(found_ips))
    new_addresses = [address for address in found_ips if address not in existing_addresses]
    insert_ip_addresses(new_addresses)

    ip_ids_by_address = load_ip_ids_by_address(found_ips)

    reactivated_ip_ids = [
        ip_ids_by_address[address] for address in existing_addresses if address in ip_ids_by_address
    ]
    if reactivated_ip_ids:
        IpAddress.query.filter(
            IpAddress.id.in_(reactivated_ip_ids), IpAddress.active.is_(False)
        ).update({IpAddress.active: True}, synchronize_session=False)

    insert_ip_batch_addresses(batch.id, [ip_ids_by_address[address] for address in found_ips])

    batch.total_found = len(found_ips)
    batch.new_count = len(new_addresses)
    batch.existing_count = len(found_ips) - len(new_addresses)
    db.session.commit()
    enqueue_ip_whois_jobs(list(ip_ids_by_address.values()))


def add_domains_to_office(office, domains, removal_date, office_files=None, redirect_target=None):
    try:
        for office_file in office_files or []:
            db.session.add(
                OfficeFile(
                    office_id=office.id,
                    file_type=office_file["file_type"],
                    filename=office_file["filename"],
                    stored_filename=office_file["stored_filename"],
                    content_type=office_file.get("content_type"),
                    removal_date=removal_date,
                )
            )

        existing_names = set(load_domain_ids_by_name(domains))
        new_domains = [domain for domain in domains if domain not in existing_names]
        insert_domains(new_domains, office.id, redirect_target=redirect_target)

        if redirect_target:
            Domain.query.filter(Domain.name.in_(domains)).update(
                {Domain.redirect_target: redirect_target}, synchronize_session=False
            )

        domain_ids_by_name = load_domain_ids_by_name(domains)

        reactivated_domain_ids = [
            domain_ids_by_name[name] for name in existing_names if name in domain_ids_by_name
        ]
        if reactivated_domain_ids:
            Domain.query.filter(
                Domain.id.in_(reactivated_domain_ids), Domain.active.is_(False)
            ).update({Domain.active: True}, synchronize_session=False)

        existing_link_ids = {
            row.domain_id
            for row in OfficeDomain.query.filter_by(office_id=office.id)
            .with_entities(OfficeDomain.domain_id)
            .all()
        }
        domain_ids = [domain_ids_by_name[name] for name in domains]
        new_link_ids = [domain_id for domain_id in domain_ids if domain_id not in existing_link_ids]
        insert_office_domains(office.id, new_link_ids, removal_date=removal_date)
        if removal_date:
            OfficeDomain.query.filter(
                OfficeDomain.office_id == office.id,
                OfficeDomain.domain_id.in_(domain_ids),
                OfficeDomain.domain_id.in_(existing_link_ids),
                OfficeDomain.removal_date.is_(None),
            ).update({OfficeDomain.removal_date: removal_date}, synchronize_session=False)

        office.total_found = OfficeDomain.query.filter_by(office_id=office.id).count()
        office.new_count += len(new_domains)
        office.existing_count += len(domains) - len(new_domains)
        db.session.commit()
        return len(new_domains), len(domains) - len(new_domains)
    except SQLAlchemyError:
        db.session.rollback()
        raise


def set_office_domains_removal_date(office, removal_date):
    updated = (
        OfficeDomain.query.filter_by(office_id=office.id)
        .update({OfficeDomain.removal_date: removal_date}, synchronize_session=False)
    )
    db.session.commit()
    return updated


def set_office_ips_removal_date(office, removal_date):
    updated = (
        IpBatch.query.filter_by(office_id=office.id)
        .update({IpBatch.removal_date: removal_date}, synchronize_session=False)
    )
    db.session.commit()
    return updated


def add_ips_to_office(office, addresses, removal_date, batch_files=None):
    try:
        batch = IpBatch(
            name=office.office_number,
            office_id=office.id,
            office_key=office_key_for(office),
            expedition_date=office.expedition_date,
            removal_date=removal_date,
            filename=ip_batch_filename(batch_files),
        )
        save_ip_batch(batch, addresses, batch_files)
        return batch.new_count, batch.existing_count
    except SQLAlchemyError:
        db.session.rollback()
        raise


def ip_batch_filename(batch_files):
    if not batch_files:
        return None
    if len(batch_files) == 1:
        return batch_files[0]["filename"]
    return f"{len(batch_files)} arquivos"


def save_uploaded_file(file, allowed_extensions, file_type):
    original_name = secure_filename(file.filename)
    suffix = Path(original_name).suffix.lower()
    if not original_name or suffix not in allowed_extensions:
        return None

    stored_name = f"{uuid4().hex}{suffix}"
    stored_path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_name
    file.save(stored_path)
    return {
        "file_type": file_type,
        "filename": original_name,
        "stored_filename": stored_name,
        "content_type": file.content_type,
        "path": stored_path,
    }


def send_stored_file(stored_file, as_attachment):
    path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_file.stored_filename
    return send_file(
        path,
        mimetype=stored_file.content_type,
        as_attachment=as_attachment,
        download_name=stored_file.filename,
    )


def delete_stored_files(stored_filenames):
    upload_folder = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    for stored_filename in stored_filenames:
        path = (upload_folder / stored_filename).resolve()
        if upload_folder not in path.parents and path != upload_folder:
            continue
        try:
            path.unlink(missing_ok=True)
        except OSError:
            current_app.logger.warning("Não foi possível remover arquivo %s", path)


def whitelisted_domain_names():
    return {row.name for row in WhitelistDomain.query.with_entities(WhitelistDomain.name).all()}


def whitelisted_ip_addresses():
    return {row.address for row in WhitelistIp.query.with_entities(WhitelistIp.address).all()}


def active_domain_names_for_office(office_id):
    whitelist = whitelisted_domain_names()
    return [
        {"name": row.name, "redirect_target": row.redirect_target}
        for row in db.session.query(Domain)
        .join(OfficeDomain, OfficeDomain.domain_id == Domain.id)
        .filter(OfficeDomain.office_id == office_id, Domain.active.is_(True))
        .order_by(Domain.name.asc())
        .all()
        if row.name not in whitelist
    ]


def active_ip_addresses_for_batch(batch_id):
    whitelist = whitelisted_ip_addresses()
    return [
        row.address
        for row in db.session.query(IpAddress)
        .join(IpBatchAddress, IpBatchAddress.ip_id == IpAddress.id)
        .filter(IpBatchAddress.batch_id == batch_id, IpAddress.active.is_(True))
        .all()
        if row.address not in whitelist
    ]


def office_ip_route_config(office):
    """Config de rotas discard dos IPs ativos do ofício (todos os lotes dele)."""
    addresses = set()
    for batch in ip_batches_query_for_office(office).all():
        addresses.update(active_ip_addresses_for_batch(batch.id))
    return build_ip_route_config(addresses) if addresses else ""


def active_domain_names_for_rpz():
    whitelist = whitelisted_domain_names()
    return [
        {"name": row.name, "redirect_target": row.redirect_target}
        for row in Domain.query.filter_by(active=True).order_by(Domain.name.asc()).all()
        if row.name not in whitelist
    ]


def active_ip_addresses_for_router():
    whitelist = whitelisted_ip_addresses()
    return [
        row.address
        for row in IpAddress.query.filter_by(active=True).all()
        if row.address not in whitelist
    ]


def ip_batches_query_for_office(office):
    return IpBatch.query.filter_by(office_id=office.id)


def ip_addresses_for_office(office):
    batch_ids = [batch.id for batch in ip_batches_query_for_office(office).all()]
    if not batch_ids:
        return []

    return (
        db.session.query(IpAddress)
        .join(IpBatchAddress, IpBatchAddress.ip_id == IpAddress.id)
        .filter(IpBatchAddress.batch_id.in_(batch_ids))
        .order_by(IpAddress.version.asc(), IpAddress.address.asc())
        .distinct()
        .all()
    )


def office_key_for(office):
    if not office.office_key:
        office.office_key = normalize_office_key(office.office_number)
        db.session.commit()
    return office.office_key


def normalize_office_key(value):
    return re.sub(r"[^0-9a-z]+", "", (value or "").lower())


def route_command_templates(settings=None):
    if settings is None:
        settings = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    ipv4 = settings.router_command_ipv4.strip() if settings and settings.router_command_ipv4 else ""
    ipv6 = settings.router_command_ipv6.strip() if settings and settings.router_command_ipv6 else ""
    return ipv4 or DEFAULT_ROUTER_COMMAND_IPV4, ipv6 or DEFAULT_ROUTER_COMMAND_IPV6


def validate_router_command_template(value, label):
    if not value:
        return None
    try:
        value.format(address="203.0.113.1")
    except (KeyError, IndexError, ValueError):
        return f"Comando {label} inválido: use exatamente o marcador {{address}} no lugar do IP/prefixo."
    return None


def to_delete_command(set_command):
    if set_command.startswith("set "):
        return "delete " + set_command[len("set ") :]
    return "delete " + set_command


def build_ip_route_config(addresses, settings=None):
    ipv4_template, ipv6_template = route_command_templates(settings)
    lines = []
    for address in sorted(addresses, key=ip_config_sort_key):
        ip_value = address.split("/", 1)[0]
        parsed = ip_address(ip_value)
        if parsed.version == 4:
            lines.append(ipv4_template.format(address=address))
        else:
            route = address if "/" in address else f"{address}/128"
            lines.append(ipv6_template.format(address=route))
    return "\n".join(lines) + ("\n" if lines else "")


def build_ip_route_delete_config(addresses, settings=None):
    ipv4_template, ipv6_template = route_command_templates(settings)
    lines = []
    for address in sorted(addresses, key=ip_config_sort_key):
        ip_value = address.split("/", 1)[0]
        parsed = ip_address(ip_value)
        if parsed.version == 4:
            lines.append(to_delete_command(ipv4_template.format(address=address)))
        else:
            route = address if "/" in address else f"{address}/128"
            lines.append(to_delete_command(ipv6_template.format(address=route)))
    return "\n".join(lines) + ("\n" if lines else "")


def current_parameter_settings():
    return ParameterSettings.query.order_by(ParameterSettings.id.asc()).first() or ParameterSettings()


def configured_router_targets():
    return load_targets(current_parameter_settings().publish_routers, "router")


def configured_bind_servers():
    return load_targets(current_parameter_settings().rpz_servers, "bind")


def configured_rpz_nameserver():
    return current_parameter_settings().rpz_nameserver or None


def configured_strict_host_key_checking():
    # NULL (nunca salvo) conta como ligado.
    return current_parameter_settings().ssh_strict_host_key_checking is not False


def ip_config_sort_key(value):
    return ip_sort_key(value) + (value,)


def removable_domain_count():
    rows = (
        db.session.query(Domain.id)
        .join(OfficeDomain, OfficeDomain.domain_id == Domain.id)
        .filter(Domain.active.is_(True), OfficeDomain.removal_date.isnot(None))
        .filter(OfficeDomain.removal_date <= date.today())
        .distinct()
        .all()
    )
    return len(rows)


def removable_ip_count():
    rows = (
        db.session.query(IpAddress.id)
        .join(IpBatchAddress, IpBatchAddress.ip_id == IpAddress.id)
        .join(IpBatch, IpBatch.id == IpBatchAddress.batch_id)
        .filter(IpAddress.active.is_(True), IpBatch.removal_date.isnot(None))
        .filter(IpBatch.removal_date <= date.today())
        .distinct()
        .all()
    )
    return len(rows)


def expired_ip_addresses_for_office(office, today):
    batch_ids = [batch.id for batch in ip_batches_query_for_office(office).all()]
    if not batch_ids:
        return []

    return (
        db.session.query(IpAddress)
        .join(IpBatchAddress, IpBatchAddress.ip_id == IpAddress.id)
        .join(IpBatch, IpBatch.id == IpBatchAddress.batch_id)
        .filter(
            IpBatch.id.in_(batch_ids),
            IpBatch.removal_date.isnot(None),
            IpBatch.removal_date <= today,
        )
        .order_by(IpAddress.version.asc(), IpAddress.address.asc())
        .distinct()
        .all()
    )


def office_has_expired_items(office, today):
    expired_domain = (
        db.session.query(OfficeDomain.id)
        .filter(
            OfficeDomain.office_id == office.id,
            OfficeDomain.removal_date.isnot(None),
            OfficeDomain.removal_date <= today,
        )
        .first()
    )
    if expired_domain:
        return True

    expired_ip = (
        db.session.query(IpBatch.id)
        .filter(
            IpBatch.office_id == office.id,
            IpBatch.removal_date.isnot(None),
            IpBatch.removal_date <= today,
        )
        .first()
    )
    return bool(expired_ip)


def load_offices_by_domain(domain_ids):
    if not domain_ids:
        return {}

    rows = (
        db.session.query(OfficeDomain.domain_id, UploadBatch.id, UploadBatch.office_number)
        .join(UploadBatch, UploadBatch.id == OfficeDomain.office_id)
        .filter(OfficeDomain.domain_id.in_(domain_ids))
        .order_by(UploadBatch.created_at.desc())
        .all()
    )
    offices_by_domain = {}
    for domain_id, office_id, office_number in rows:
        offices_by_domain.setdefault(domain_id, []).append(
            {"id": office_id, "number": office_number}
        )
    return offices_by_domain


def load_batches_by_ip(ip_ids):
    if not ip_ids:
        return {}

    rows = (
        db.session.query(IpBatchAddress.ip_id, IpBatch.id, IpBatch.name)
        .join(IpBatch, IpBatch.id == IpBatchAddress.batch_id)
        .filter(IpBatchAddress.ip_id.in_(ip_ids))
        .order_by(IpBatch.created_at.desc())
        .all()
    )
    batches_by_ip = {}
    for ip_id, batch_id, batch_name in rows:
        batches_by_ip.setdefault(ip_id, []).append({"id": batch_id, "name": batch_name})
    return batches_by_ip


def load_ip_removal_by_ip(ip_ids, batch_ids):
    """Data de remocao "atual" de cada IP dentro do oficio: a do lote mais recente
    que o referencia (nao a mais antiga entre todos os oficios que ja o citaram),
    para que reimportar um IP num oficio novo sem prazo limpe o status "expirado"
    de um lote antigo em vez de ficar preso a ele para sempre."""
    if not ip_ids or not batch_ids:
        return {}

    rows = (
        db.session.query(IpBatchAddress.ip_id, IpBatch.removal_date)
        .join(IpBatch, IpBatch.id == IpBatchAddress.batch_id)
        .filter(IpBatchAddress.ip_id.in_(ip_ids), IpBatch.id.in_(batch_ids))
        .order_by(IpBatch.created_at.desc())
        .all()
    )
    removal_by_ip = {}
    for ip_id, removal_date in rows:
        removal_by_ip.setdefault(ip_id, removal_date)
    return removal_by_ip


def load_users_by_id(user_ids):
    user_ids = {user_id for user_id in user_ids if user_id}
    if not user_ids:
        return {}

    rows = User.query.filter(User.id.in_(user_ids)).all()
    return {user.id: user for user in rows}


def load_domain_ids_by_name(domain_names):
    domain_ids = {}
    for chunk in chunked(domain_names, QUERY_CHUNK_SIZE):
        rows = Domain.query.filter(Domain.name.in_(chunk)).with_entities(Domain.id, Domain.name).all()
        domain_ids.update({name: domain_id for domain_id, name in rows})
    return domain_ids


def load_ip_ids_by_address(addresses):
    ip_ids = {}
    for chunk in chunked(addresses, QUERY_CHUNK_SIZE):
        rows = (
            IpAddress.query.filter(IpAddress.address.in_(chunk))
            .with_entities(IpAddress.id, IpAddress.address)
            .all()
        )
        ip_ids.update({address: ip_id for ip_id, address in rows})
    return ip_ids


def insert_domains(domain_names, batch_id, redirect_target=None):
    for chunk in chunked(domain_names, BULK_INSERT_CHUNK_SIZE):
        rows = [
            {
                "name": domain_name,
                "first_seen_batch_id": batch_id,
                "redirect_target": redirect_target,
            }
            for domain_name in chunk
        ]
        db.session.execute(insert(Domain).prefix_with("IGNORE"), rows)


def insert_ip_addresses(addresses):
    for chunk in chunked(addresses, BULK_INSERT_CHUNK_SIZE):
        rows = [
            {
                "address": address,
                "version": ip_address(address.split("/", 1)[0]).version,
            }
            for address in chunk
        ]
        db.session.execute(insert(IpAddress).prefix_with("IGNORE"), rows)


def insert_office_domains(batch_id, domain_ids, removal_date=None):
    for chunk in chunked(domain_ids, BULK_INSERT_CHUNK_SIZE):
        rows = [
            {"office_id": batch_id, "domain_id": domain_id, "removal_date": removal_date}
            for domain_id in chunk
        ]
        db.session.execute(insert(OfficeDomain).prefix_with("IGNORE"), rows)


def insert_ip_batch_addresses(batch_id, ip_ids):
    for chunk in chunked(ip_ids, BULK_INSERT_CHUNK_SIZE):
        rows = [{"batch_id": batch_id, "ip_id": ip_id} for ip_id in chunk]
        db.session.execute(insert(IpBatchAddress).prefix_with("IGNORE"), rows)


def chunked(values, size):
    for index in range(0, len(values), size):
        yield values[index : index + size]


def safe_filename(value):
    return secure_filename(value).replace("_", "-") or "sem-numero"
