import json
import secrets
from datetime import date
from pathlib import Path
from uuid import uuid4

from flask import Response, current_app, jsonify, request
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from ..extractors import (
    extract_domains,
    extract_ip_addresses,
    extract_office_metadata,
    normalize_domain,
    normalize_ip_address,
)
from ..models import (
    CompanySettings,
    Deployment,
    Domain,
    IpAddress,
    IpBatch,
    IpBatchAddress,
    IpBatchFile,
    OfficeDomain,
    OfficeFile,
    ParameterSettings,
    PublicationLock,
    UploadBatch,
    User,
    WhitelistDomain,
    WhitelistIp,
    db,
)
from ..services import (
    ALLOWED_EXTENSIONS,
    INTIMATION_EXTENSIONS,
    IP_ALLOWED_EXTENSIONS,
    PROCESS_NUMBER_PATTERN,
    PUBLISH_LOCK_NAME,
    acquire_publish_lock,
    active_domain_names_for_office,
    active_domain_names_for_rpz,
    active_ip_addresses_for_batch,
    active_ip_addresses_for_router,
    add_domains_to_office,
    add_ips_to_office,
    build_communication_config,
    configured_bind_servers,
    configured_router_targets,
    configured_rpz_nameserver,
    configured_strict_host_key_checking,
    delete_stored_files,
    DEFAULT_ROUTER_COMMAND_IPV4,
    DEFAULT_ROUTER_COMMAND_IPV6,
    expired_ip_addresses_for_office,
    ip_addresses_for_office,
    ip_batches_query_for_office,
    ip_config_sort_key,
    build_ip_route_config,
    build_ip_route_delete_config,
    load_batches_by_ip,
    load_ip_removal_by_ip,
    load_json_list,
    load_offices_by_domain,
    load_users_by_id,
    normalize_office_key,
    normalize_sei_numbers,
    office_has_expired_items,
    parse_date,
    parse_manual_domains,
    parse_manual_ips,
    perform_office_deletion,
    perform_office_domain_toggle,
    perform_office_ip_toggle,
    release_publish_lock,
    removable_domain_count,
    removable_ip_count,
    safe_filename,
    save_uploaded_file,
    send_stored_file,
    set_office_domains_removal_date,
    set_office_ips_removal_date,
    start_router_deployment,
    validate_router_command_template,
    whitelisted_domain_names,
    whitelisted_ip_addresses,
)
from ..backup import (
    RESTORE_CONFIRM_PHRASE,
    backup_filename,
    build_database_backup,
    build_files_backup,
    restore_database,
    restore_files,
)
from ..abuse_imap import ImapConfig, ReadOnlyMailbox, connect as imap_connect
from ..mailer import (
    SMTP_SECURITIES,
    describe_error as describe_mail_error,
    parse_recipients,
    smtp_config_problem,
    test_connection as test_smtp_connection,
)
from ..rpz import build_rpz_zone
from ..ssh_settings import dump_targets, load_targets, merge_targets, public_targets
from ..ssh_publish import publish_ip_routes, publish_zone
from ..whois_jobs import enqueue_ip_whois_jobs, load_whois_by_ip, load_whois_jobs_by_ip
from . import api_bp
from .auth import current_actor_user, hash_token, require_auth

MAX_PER_PAGE = 100


def parse_bool_param(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "sim")


def publish_lock_message():
    lock = PublicationLock.query.get(PUBLISH_LOCK_NAME)
    owner = f" por {lock.owner}" if lock and lock.owner else ""
    return f"Já existe uma publicação em andamento{owner}. Aguarde finalizar para publicar novamente."


def iso_utc(value):
    """Serializa um datetime naive (armazenado em UTC) marcando o fuso explicitamente,
    para o navegador converter corretamente para o horário local do usuário."""
    if value is None:
        return None
    return value.isoformat() + "Z"


def serialize_office(office):
    return {
        "id": office.id,
        "office_number": office.office_number,
        "process_number": office.process_number,
        "sei_numbers": office.sei_numbers,
        "expedition_date": office.expedition_date.isoformat() if office.expedition_date else None,
        "removal_date": office.removal_date.isoformat() if office.removal_date else None,
        "notification_sent_at": iso_utc(office.notification_sent_at),
        "total_found": office.total_found,
        "new_count": office.new_count,
        "existing_count": office.existing_count,
        "created_at": iso_utc(office.created_at),
    }


def serialize_domain(domain):
    return {
        "id": domain.id,
        "name": domain.name,
        "active": domain.active,
        "redirect_target": domain.redirect_target,
        "created_at": iso_utc(domain.created_at),
        "updated_at": iso_utc(domain.updated_at),
    }


def serialize_ip_address(ip):
    return {
        "id": ip.id,
        "address": ip.address,
        "version": ip.version,
        "active": ip.active,
        "created_at": iso_utc(ip.created_at),
    }


def serialize_whois_cache(cache):
    return {
        "asn": cache.asn,
        "as_name": cache.as_name,
        "bgp_prefix": cache.bgp_prefix,
        "registry": cache.registry,
        "country": cache.country,
        "rdap_name": cache.rdap_name,
        "rdap_handle": cache.rdap_handle,
        "rdap_country": cache.rdap_country,
        "error": cache.error,
        "updated_at": iso_utc(cache.updated_at),
    }


def serialize_whois_job(job):
    return {
        "status": job.status,
        "attempts": job.attempts,
        "error": job.error,
        "started_at": iso_utc(job.started_at),
        "finished_at": iso_utc(job.finished_at),
    }


def serialize_domain_with_offices(domain, offices_by_domain, whitelisted_names=None):
    data = serialize_domain(domain)
    data["offices"] = offices_by_domain.get(domain.id, [])
    data["whitelisted"] = domain.name in whitelisted_names if whitelisted_names is not None else False
    return data


def serialize_ip_address_with_context(
    ip, batches_by_ip, whois_by_ip, whois_jobs_by_ip, whitelisted_addresses=None
):
    data = serialize_ip_address(ip)
    data["batches"] = batches_by_ip.get(ip.id, [])
    whois = whois_by_ip.get(ip.id)
    data["whois"] = serialize_whois_cache(whois) if whois else None
    job = whois_jobs_by_ip.get(ip.id)
    data["whois_job"] = serialize_whois_job(job) if job else None
    data["whitelisted"] = (
        ip.address in whitelisted_addresses if whitelisted_addresses is not None else False
    )
    return data


def serialize_whitelist_domain(entry):
    return {
        "id": entry.id,
        "name": entry.name,
        "reason": entry.reason,
        "created_at": iso_utc(entry.created_at),
    }


def serialize_whitelist_ip(entry):
    return {
        "id": entry.id,
        "address": entry.address,
        "reason": entry.reason,
        "created_at": iso_utc(entry.created_at),
    }


def serialize_office_file(file):
    return {
        "id": file.id,
        "file_type": file.file_type,
        "filename": file.filename,
        "content_type": file.content_type,
        "removal_date": file.removal_date.isoformat() if file.removal_date else None,
        "created_at": iso_utc(file.created_at),
    }


def serialize_ip_batch(batch):
    return {
        "id": batch.id,
        "name": batch.name,
        "filename": batch.filename,
        "expedition_date": batch.expedition_date.isoformat() if batch.expedition_date else None,
        "removal_date": batch.removal_date.isoformat() if batch.removal_date else None,
        "total_found": batch.total_found,
        "new_count": batch.new_count,
        "existing_count": batch.existing_count,
        "created_at": iso_utc(batch.created_at),
    }


def serialize_ip_batch_file(file):
    return {
        "id": file.id,
        "batch_id": file.batch_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "created_at": iso_utc(file.created_at),
    }


def serialize_deployment(deployment):
    return {
        "id": deployment.id,
        "deployment_type": deployment.deployment_type,
        "status": deployment.status,
        "domain_count": deployment.domain_count,
        "ip_count": deployment.ip_count,
        "message": deployment.message,
        "created_at": iso_utc(deployment.created_at),
    }


def paginated_response(query, serializer, page, per_page):
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(
        items=[serializer(item) for item in pagination.items],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


def read_app_version():
    version_file = Path(__file__).resolve().parent.parent.parent / "VERSION"
    try:
        return version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


APP_VERSION = read_app_version()


@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify(status="ok", version=APP_VERSION)


@api_bp.route("/auth/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    user = User.query.filter_by(username=username).first()
    if not user or not user.active or not user.check_password(password):
        return jsonify(error="Usuário ou senha inválidos."), 401

    token = secrets.token_hex(32)
    user.api_token_hash = hash_token(token)
    db.session.commit()

    return jsonify(
        token=token,
        user={"id": user.id, "username": user.username, "abuse_access": bool(user.abuse_access)},
    )


@api_bp.route("/auth/logout", methods=["POST"])
@require_auth
def logout():
    actor_user = current_actor_user()
    if not actor_user:
        return jsonify(error="Logout só se aplica a autenticação por usuário (Bearer token)."), 400

    actor_user.api_token_hash = None
    db.session.commit()
    return jsonify(status="logged_out")


@api_bp.route("/auth/me", methods=["GET"])
@require_auth
def me():
    actor_user = current_actor_user()
    if actor_user:
        return jsonify(
            type="user",
            id=actor_user.id,
            username=actor_user.username,
            abuse_access=bool(actor_user.abuse_access),
        )
    return jsonify(type="service")


@api_bp.route("/offices", methods=["GET"])
@require_auth
def list_offices():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), MAX_PER_PAGE)
    q = request.args.get("q", "", type=str).strip()

    query = UploadBatch.query
    if q:
        query = query.filter(
            or_(
                UploadBatch.office_number.like(f"%{q}%"),
                UploadBatch.process_number.like(f"%{q}%"),
            )
        )

    pagination = query.order_by(
        UploadBatch.expedition_date.is_(None),
        UploadBatch.expedition_date.desc(),
        UploadBatch.created_at.desc(),
    ).paginate(page=page, per_page=per_page, error_out=False)
    today = date.today()
    users_by_id = load_users_by_id(
        {batch.created_by_user_id for batch in pagination.items if batch.created_by_user_id}
    )

    items = []
    for batch in pagination.items:
        item = serialize_office(batch)
        item["ip_count"] = len(ip_addresses_for_office(batch))
        item["expired"] = office_has_expired_items(batch, today)
        creator = users_by_id.get(batch.created_by_user_id)
        item["created_by_username"] = creator.username if creator else None
        items.append(item)

    return jsonify(
        items=items,
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


def find_office(office_id):
    return UploadBatch.query.get(office_id)


@api_bp.route("/offices/<int:office_id>", methods=["GET"])
@require_auth
def get_office(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    detail = serialize_office(office)

    created_by_user = User.query.get(office.created_by_user_id) if office.created_by_user_id else None
    detail["created_by_user"] = (
        {"id": created_by_user.id, "username": created_by_user.username} if created_by_user else None
    )

    files = OfficeFile.query.filter_by(office_id=office.id).order_by(OfficeFile.created_at.asc()).all()
    detail["files"] = [serialize_office_file(file) for file in files]

    domain_rows = (
        db.session.query(Domain, OfficeDomain.removal_date)
        .join(OfficeDomain, OfficeDomain.domain_id == Domain.id)
        .filter(OfficeDomain.office_id == office.id)
        .order_by(Domain.name.asc())
        .all()
    )
    detail["domains"] = [
        {**serialize_domain(domain), "removal_date": removal_date.isoformat() if removal_date else None}
        for domain, removal_date in domain_rows
    ]

    ip_batches_for_office = ip_batches_query_for_office(office).order_by(IpBatch.created_at.desc()).all()
    detail["ip_batches"] = [serialize_ip_batch(batch) for batch in ip_batches_for_office]

    ip_files = []
    if ip_batches_for_office:
        ip_files = (
            IpBatchFile.query.filter(
                IpBatchFile.batch_id.in_([batch.id for batch in ip_batches_for_office])
            )
            .order_by(IpBatchFile.created_at.asc())
            .all()
        )
    detail["ip_files"] = [serialize_ip_batch_file(file) for file in ip_files]

    ip_addresses = ip_addresses_for_office(office)
    ip_removal_by_ip = load_ip_removal_by_ip(
        [address.id for address in ip_addresses],
        [batch.id for batch in ip_batches_for_office],
    )
    detail["ip_addresses"] = [
        {
            **serialize_ip_address(address),
            "removal_date": (
                ip_removal_by_ip[address.id].isoformat() if ip_removal_by_ip.get(address.id) else None
            ),
        }
        for address in ip_addresses
    ]

    detail["expired_ip_count"] = len(expired_ip_addresses_for_office(office, date.today()))
    detail["ip_stats"] = {
        "total": len(ip_addresses),
        "new": sum(batch.new_count for batch in ip_batches_for_office),
        "existing": sum(batch.existing_count for batch in ip_batches_for_office),
    }

    return jsonify(detail)


@api_bp.route("/offices", methods=["POST"])
@require_auth
def create_office():
    is_multipart = bool(request.content_type) and request.content_type.startswith(
        "multipart/form-data"
    )
    payload = request.form if is_multipart else (request.get_json(silent=True) or {})
    intimation = request.files.get("intimation_pdf") if is_multipart else None

    office_number = (payload.get("office_number") or "").strip()
    process_number = (payload.get("process_number") or "").strip()
    sei_numbers_raw = payload.get("sei_numbers") or ""
    if isinstance(sei_numbers_raw, list):
        sei_numbers_raw = ", ".join(sei_numbers_raw)
    sei_numbers = normalize_sei_numbers(sei_numbers_raw)

    try:
        expedition_date = parse_date((payload.get("expedition_date") or "").strip())
    except ValueError:
        return jsonify(error="Data de expedição inválida. Use o formato AAAA-MM-DD."), 400

    if not process_number:
        return jsonify(error="Informe o número do processo."), 400
    if not PROCESS_NUMBER_PATTERN.match(process_number):
        return (
            jsonify(error="Número do processo inválido. Use o formato 53500.099328/2024-86."),
            400,
        )

    intimation_file = None
    if intimation and intimation.filename:
        intimation_file = save_uploaded_file(intimation, INTIMATION_EXTENSIONS, "intimation")
        if not intimation_file:
            return jsonify(error="A intimação deve ser enviada em PDF ou HTML."), 400

        try:
            metadata = extract_office_metadata(intimation_file["path"])
        except Exception as exc:
            delete_stored_files([intimation_file["stored_filename"]])
            return jsonify(error=f"Não foi possível processar a intimação: {exc}"), 422

        if not office_number and metadata["office_number"]:
            office_number = metadata["office_number"]
        if not sei_numbers and metadata["sei_numbers"]:
            sei_numbers = normalize_sei_numbers(",".join(metadata["sei_numbers"]))
        if not expedition_date and metadata["expedition_date"]:
            expedition_date = metadata["expedition_date"]

    if not office_number:
        if intimation_file:
            delete_stored_files([intimation_file["stored_filename"]])
        return (
            jsonify(
                error="Informe o número do ofício ou envie uma intimação contendo esse número."
            ),
            400,
        )

    actor_user = current_actor_user()

    office = UploadBatch(
        office_number=office_number,
        process_number=process_number,
        created_by_user_id=actor_user.id if actor_user else None,
        sei_numbers=sei_numbers,
        office_key=normalize_office_key(office_number),
        expedition_date=expedition_date,
        filename="oficio-sem-lista.txt",
        stored_filename=f"office-{uuid4().hex}.txt",
    )
    db.session.add(office)
    db.session.flush()

    if intimation_file:
        db.session.add(
            OfficeFile(
                office_id=office.id,
                file_type="intimation",
                filename=intimation_file["filename"],
                stored_filename=intimation_file["stored_filename"],
                content_type=intimation_file.get("content_type"),
            )
        )

    db.session.commit()

    return jsonify(serialize_office(office)), 201


@api_bp.route("/offices/<int:office_id>", methods=["PATCH"])
@require_auth
def update_office(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    office_number = (payload.get("office_number") or "").strip()
    if not office_number:
        return jsonify(error="Informe o número do ofício."), 400

    office_key = normalize_office_key(office_number)
    if not office_key:
        return jsonify(error="Informe um número de ofício válido."), 400

    existing = UploadBatch.query.filter(
        UploadBatch.id != office.id, UploadBatch.office_key == office_key
    ).first()
    if existing:
        return jsonify(error="Já existe outro ofício com esse número."), 409

    office.office_number = office_number
    office.office_key = office_key
    IpBatch.query.filter_by(office_id=office.id).update(
        {IpBatch.name: office_number, IpBatch.office_key: office_key},
        synchronize_session=False,
    )
    db.session.commit()

    return jsonify(serialize_office(office))


@api_bp.route("/offices/<int:office_id>", methods=["DELETE"])
@require_auth
def delete_office(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    confirmed_number = (payload.get("confirm_office_number") or "").strip()
    if confirmed_number != office.office_number:
        return (
            jsonify(
                error="Confirmação inválida. Envie o campo confirm_office_number com o "
                f"número exato do ofício ({office.office_number!r}) para confirmar a exclusão."
            ),
            400,
        )

    try:
        result = perform_office_deletion(office)
    except SQLAlchemyError as exc:
        current_app.logger.exception("Falha ao remover ofício via API")
        return jsonify(error=f"Não foi possível remover o ofício: {exc}"), 500

    return jsonify(status="deleted", office_id=office_id, **result)


@api_bp.route("/offices/<int:office_id>/domains/files", methods=["POST"])
@require_auth
def add_office_domain_files(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    files = [file for file in request.files.getlist("domain_files") if file and file.filename]
    try:
        removal_date = parse_date(request.form.get("removal_date", "").strip())
    except ValueError:
        return jsonify(error="Data de remoção inválida."), 400

    redirect_target_raw = request.form.get("redirect_target", "").strip()
    redirect_target = normalize_domain(redirect_target_raw) if redirect_target_raw else None
    if redirect_target_raw and not redirect_target:
        return jsonify(error="Domínio de redirecionamento inválido."), 400

    if not files:
        return jsonify(error="Selecione ao menos um arquivo de domínios."), 400

    found_domains = set()
    office_files = []
    for file in files:
        saved_file = save_uploaded_file(file, ALLOWED_EXTENSIONS, "import")
        if not saved_file:
            delete_stored_files([f["stored_filename"] for f in office_files])
            return jsonify(error="Formato não suportado. Envie PDF, ODS, XLS ou XLSX."), 400

        office_files.append(saved_file)
        try:
            found_domains.update(extract_domains(saved_file["path"]))
        except Exception as exc:
            delete_stored_files([f["stored_filename"] for f in office_files])
            return (
                jsonify(error=f"Não foi possível processar o arquivo {saved_file['filename']}: {exc}"),
                422,
            )

    if not found_domains:
        delete_stored_files([f["stored_filename"] for f in office_files])
        return jsonify(error="Nenhum domínio válido foi encontrado nos arquivos."), 422

    try:
        added, existing = add_domains_to_office(
            office, sorted(found_domains), removal_date, office_files, redirect_target=redirect_target
        )
    except SQLAlchemyError as exc:
        return jsonify(error=f"Não foi possível salvar os domínios: {exc}"), 500

    return jsonify(added=added, existing=existing)


@api_bp.route("/offices/<int:office_id>/domains/manual", methods=["POST"])
@require_auth
def add_office_manual_domains(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    try:
        removal_date = parse_date((payload.get("removal_date") or "").strip())
    except ValueError:
        return jsonify(error="Data de remoção inválida."), 400

    domains_raw = payload.get("domains") or ""
    if isinstance(domains_raw, list):
        domains_raw = "\n".join(domains_raw)
    domains = parse_manual_domains(domains_raw)
    if not domains:
        return jsonify(error="Informe ao menos um domínio válido."), 400

    redirect_target_raw = (payload.get("redirect_target") or "").strip()
    redirect_target = normalize_domain(redirect_target_raw) if redirect_target_raw else None
    if redirect_target_raw and not redirect_target:
        return jsonify(error="Domínio de redirecionamento inválido."), 400

    try:
        added, existing = add_domains_to_office(
            office, domains, removal_date, redirect_target=redirect_target
        )
    except SQLAlchemyError as exc:
        return jsonify(error=f"Não foi possível salvar os domínios: {exc}"), 500

    return jsonify(added=added, existing=existing)


@api_bp.route("/offices/<int:office_id>/domains/removal-date", methods=["PATCH"])
@require_auth
def update_office_domains_removal_date(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    try:
        removal_date = parse_date((payload.get("removal_date") or "").strip())
    except ValueError:
        return jsonify(error="Data de remoção inválida."), 400

    updated = set_office_domains_removal_date(office, removal_date)
    return jsonify(updated=updated, removal_date=removal_date.isoformat() if removal_date else None)


@api_bp.route("/offices/<int:office_id>/ips/files", methods=["POST"])
@require_auth
def add_office_ip_files(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    files = [file for file in request.files.getlist("ip_files") if file and file.filename]
    try:
        removal_date = parse_date(request.form.get("removal_date", "").strip())
    except ValueError:
        return jsonify(error="Data de remoção inválida."), 400

    if not files:
        return jsonify(error="Selecione ao menos um arquivo de IPs."), 400

    found_ips = set()
    batch_files = []
    for file in files:
        saved_file = save_uploaded_file(file, IP_ALLOWED_EXTENSIONS, "ip_import")
        if not saved_file:
            delete_stored_files([f["stored_filename"] for f in batch_files])
            return jsonify(error="Formato não suportado. Envie PDF, XLS ou XLSX."), 400

        batch_files.append(saved_file)
        try:
            found_ips.update(extract_ip_addresses(saved_file["path"]))
        except Exception as exc:
            delete_stored_files([f["stored_filename"] for f in batch_files])
            return (
                jsonify(error=f"Não foi possível processar o arquivo {saved_file['filename']}: {exc}"),
                422,
            )

    if not found_ips:
        delete_stored_files([f["stored_filename"] for f in batch_files])
        return jsonify(error="Nenhum IP válido foi encontrado nos arquivos."), 422

    try:
        added, existing = add_ips_to_office(
            office, sorted(found_ips, key=ip_config_sort_key), removal_date, batch_files
        )
    except SQLAlchemyError as exc:
        return jsonify(error=f"Não foi possível salvar os IPs: {exc}"), 500

    return jsonify(added=added, existing=existing)


@api_bp.route("/offices/<int:office_id>/ips/manual", methods=["POST"])
@require_auth
def add_office_manual_ips(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    try:
        removal_date = parse_date((payload.get("removal_date") or "").strip())
    except ValueError:
        return jsonify(error="Data de remoção inválida."), 400

    ips_raw = payload.get("ips") or ""
    if isinstance(ips_raw, list):
        ips_raw = "\n".join(ips_raw)
    addresses = parse_manual_ips(ips_raw)
    if not addresses:
        return jsonify(error="Informe ao menos um IP válido."), 400

    try:
        added, existing = add_ips_to_office(office, addresses, removal_date)
    except SQLAlchemyError as exc:
        return jsonify(error=f"Não foi possível salvar os IPs: {exc}"), 500

    return jsonify(added=added, existing=existing)


@api_bp.route("/offices/<int:office_id>/ips/removal-date", methods=["PATCH"])
@require_auth
def update_office_ips_removal_date(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    try:
        removal_date = parse_date((payload.get("removal_date") or "").strip())
    except ValueError:
        return jsonify(error="Data de remoção inválida."), 400

    updated = set_office_ips_removal_date(office, removal_date)
    return jsonify(updated=updated, removal_date=removal_date.isoformat() if removal_date else None)


def office_zone_download(office_id, filename_suffix):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    names = active_domain_names_for_office(office.id)
    body = build_rpz_zone(names, configured_rpz_nameserver())
    filename = f"oficio-{safe_filename(office.office_number)}-{filename_suffix}"
    return Response(
        body, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@api_bp.route("/offices/<int:office_id>/bind.txt", methods=["GET"])
@require_auth
def office_bind_download(office_id):
    return office_zone_download(office_id, "bind.txt")


@api_bp.route("/offices/<int:office_id>/db.rpz.zone", methods=["GET"])
@require_auth
def office_rpz_download(office_id):
    return office_zone_download(office_id, "db.rpz.zone")


@api_bp.route("/offices/<int:office_id>/expired-ips-delete.txt", methods=["GET"])
@require_auth
def office_expired_ip_delete_config_download(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    addresses = [address.address for address in expired_ip_addresses_for_office(office, date.today())]
    body = build_ip_route_delete_config(addresses)
    filename = f"oficio-{safe_filename(office.office_number)}-ips-expirados-delete.txt"
    return Response(
        body, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@api_bp.route("/offices/<int:office_id>/deploy-ips", methods=["POST"])
@require_auth
def deploy_office_ip_routes(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") is not True:
        return (
            jsonify(
                error='Ação real de publicação no roteador. Envie {"confirm": true} no corpo '
                "da requisição para confirmar."
            ),
            400,
        )

    actor_user = current_actor_user()
    whitelisted_addresses = whitelisted_ip_addresses()
    addresses = [
        address.address
        for address in ip_addresses_for_office(office)
        if address.active and address.address not in whitelisted_addresses
    ]
    config = build_ip_route_config(addresses)

    if not acquire_publish_lock(owner=actor_user.username if actor_user else "api"):
        return jsonify(error=publish_lock_message()), 409

    deployment = Deployment(
        deployment_type="router-office",
        user_id=actor_user.id if actor_user else None,
        status="running",
        domain_count=0,
        ip_count=len(addresses),
    )
    db.session.add(deployment)
    db.session.commit()
    start_router_deployment(
        deployment.id,
        config,
        "Falha ao publicar IPs do ofício no roteador",
        lock_name=PUBLISH_LOCK_NAME,
        routers=configured_router_targets(),
    )

    return jsonify(status="running", deployment_id=deployment.id, ip_count=len(addresses)), 202


@api_bp.route("/offices/<int:office_id>/deploy-expired-ips-delete", methods=["POST"])
@require_auth
def deploy_office_expired_ip_delete_routes(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") is not True:
        return (
            jsonify(
                error='Ação real de publicação no roteador. Envie {"confirm": true} no corpo '
                "da requisição para confirmar."
            ),
            400,
        )

    addresses = [address.address for address in expired_ip_addresses_for_office(office, date.today())]
    if not addresses:
        return jsonify(error="Este ofício não possui IPs expirados ativos para remover do roteador."), 400

    actor_user = current_actor_user()
    config = build_ip_route_delete_config(addresses)

    if not acquire_publish_lock(owner=actor_user.username if actor_user else "api"):
        return jsonify(error=publish_lock_message()), 409

    deployment = Deployment(
        deployment_type="router-office-expired-delete",
        user_id=actor_user.id if actor_user else None,
        status="running",
        domain_count=0,
        ip_count=len(addresses),
    )
    db.session.add(deployment)
    db.session.commit()
    start_router_deployment(
        deployment.id,
        config,
        "Falha ao remover IPs expirados do ofício no roteador",
        lock_name=PUBLISH_LOCK_NAME,
        routers=configured_router_targets(),
    )

    return jsonify(status="running", deployment_id=deployment.id, ip_count=len(addresses)), 202


@api_bp.route("/offices/<int:office_id>/disable-domains", methods=["POST"])
@require_auth
def disable_office_domains(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    result = perform_office_domain_toggle(office)
    if result is None:
        return jsonify(error="Este ofício não possui domínios para desativar."), 400
    if result["action"] == "none":
        return (
            jsonify(
                error="Nenhum domínio foi desativado. Todos também aparecem em ofícios com "
                "expedição igual ou mais recente."
            ),
            409,
        )
    return jsonify(**result)


@api_bp.route("/offices/<int:office_id>/toggle-ips", methods=["POST"])
@require_auth
def toggle_office_ips(office_id):
    office = find_office(office_id)
    if not office:
        return jsonify(error="Ofício não encontrado."), 404

    result = perform_office_ip_toggle(office)
    if result is None:
        return jsonify(error="Este ofício não possui IPs vinculados."), 400
    if result.get("no_ips"):
        return jsonify(error="Este ofício não possui IPs para alterar."), 400
    if result["action"] == "none":
        return (
            jsonify(
                error="Nenhum IP foi desativado. Todos também aparecem em ofícios com "
                "expedição igual ou mais recente."
            ),
            409,
        )
    return jsonify(**result)


@api_bp.route("/offices/<int:office_id>/files/<int:file_id>", methods=["GET"])
@require_auth
def office_file_view(office_id, file_id):
    office_file = OfficeFile.query.filter_by(id=file_id, office_id=office_id).first()
    if not office_file:
        return jsonify(error="Arquivo não encontrado."), 404
    return send_stored_file(office_file, as_attachment=False)


@api_bp.route("/offices/<int:office_id>/files/<int:file_id>/download", methods=["GET"])
@require_auth
def office_file_download(office_id, file_id):
    office_file = OfficeFile.query.filter_by(id=file_id, office_id=office_id).first()
    if not office_file:
        return jsonify(error="Arquivo não encontrado."), 404
    return send_stored_file(office_file, as_attachment=True)


@api_bp.route("/domains", methods=["GET"])
@require_auth
def list_domains():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), MAX_PER_PAGE)
    q = request.args.get("q", "", type=str).strip()
    active = parse_bool_param(request.args.get("active"))

    query = Domain.query
    if q:
        query = query.filter(Domain.name.like(f"%{q}%"))
    if active is not None:
        query = query.filter(Domain.active == active)

    pagination = query.order_by(Domain.name.asc()).paginate(page=page, per_page=per_page, error_out=False)
    offices_by_domain = load_offices_by_domain([domain.id for domain in pagination.items])
    whitelisted_names = whitelisted_domain_names()

    return jsonify(
        items=[
            serialize_domain_with_offices(domain, offices_by_domain, whitelisted_names)
            for domain in pagination.items
        ],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


@api_bp.route("/domains/<int:domain_id>/toggle", methods=["POST"])
@require_auth
def toggle_domain(domain_id):
    domain = Domain.query.get(domain_id)
    if not domain:
        return jsonify(error="Domínio não encontrado."), 404
    domain.active = not domain.active
    db.session.commit()
    return jsonify(serialize_domain(domain))


@api_bp.route("/rpz", methods=["GET"])
@require_auth
def rpz_preview():
    names = active_domain_names_for_rpz()
    zone = build_rpz_zone(names, configured_rpz_nameserver())
    return jsonify(domain_count=len(names), zone=zone)


@api_bp.route("/rpz/db.rpz.zone", methods=["GET"])
@require_auth
def rpz_download():
    names = active_domain_names_for_rpz()
    zone = build_rpz_zone(names, configured_rpz_nameserver())
    return Response(
        zone, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=db.rpz.zone"}
    )


@api_bp.route("/ip-addresses", methods=["GET"])
@require_auth
def list_ip_addresses():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), MAX_PER_PAGE)
    q = request.args.get("q", "", type=str).strip()
    active = parse_bool_param(request.args.get("active"))

    query = IpAddress.query
    if q:
        query = query.filter(IpAddress.address.like(f"%{q}%"))
    if active is not None:
        query = query.filter(IpAddress.active == active)

    pagination = query.order_by(IpAddress.version.asc(), IpAddress.address.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    ip_ids = [address.id for address in pagination.items]
    batches_by_ip = load_batches_by_ip(ip_ids)
    whois_by_ip = load_whois_by_ip(ip_ids)
    whois_jobs_by_ip = load_whois_jobs_by_ip(ip_ids)
    whitelisted_addresses = whitelisted_ip_addresses()

    return jsonify(
        items=[
            serialize_ip_address_with_context(
                address, batches_by_ip, whois_by_ip, whois_jobs_by_ip, whitelisted_addresses
            )
            for address in pagination.items
        ],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


@api_bp.route("/ip-addresses/<int:ip_id>/toggle", methods=["POST"])
@require_auth
def toggle_ip_address(ip_id):
    address = IpAddress.query.get(ip_id)
    if not address:
        return jsonify(error="IP não encontrado."), 404
    address.active = not address.active
    db.session.commit()
    return jsonify(serialize_ip_address(address))


@api_bp.route("/ip-addresses/whois-refresh", methods=["POST"])
@require_auth
def refresh_ip_whois_route():
    payload = request.get_json(silent=True) or {}
    ip_ids = payload.get("ip_ids")

    if ip_ids is not None:
        try:
            ids = [int(ip_id) for ip_id in ip_ids]
        except (TypeError, ValueError):
            return jsonify(error="ip_ids deve ser uma lista de números inteiros."), 400
    else:
        q = (payload.get("q") or "").strip()
        active = parse_bool_param(payload.get("active"))
        query = IpAddress.query
        if q:
            query = query.filter(IpAddress.address.like(f"%{q}%"))
        if active is not None:
            query = query.filter(IpAddress.active == active)
        ids = [row.id for row in query.with_entities(IpAddress.id).all()]

    result = enqueue_ip_whois_jobs(ids)
    return jsonify(**result)


@api_bp.route("/ip-addresses/config.txt", methods=["GET"])
@require_auth
def ip_config_download():
    addresses = active_ip_addresses_for_router()
    body = build_ip_route_config(addresses)
    return Response(
        body,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=edge-router-discard-routes.txt"},
    )


@api_bp.route("/ip-batches/<int:batch_id>", methods=["GET"])
@require_auth
def get_ip_batch(batch_id):
    batch = IpBatch.query.get(batch_id)
    if not batch:
        return jsonify(error="Lote de IPs não encontrado."), 404

    files = IpBatchFile.query.filter_by(batch_id=batch.id).order_by(IpBatchFile.created_at.asc()).all()
    addresses = (
        db.session.query(IpAddress)
        .join(IpBatchAddress, IpBatchAddress.ip_id == IpAddress.id)
        .filter(IpBatchAddress.batch_id == batch.id)
        .order_by(IpAddress.version.asc(), IpAddress.address.asc())
        .all()
    )

    detail = serialize_ip_batch(batch)
    detail["office_id"] = batch.office_id
    detail["files"] = [serialize_ip_batch_file(file) for file in files]
    detail["addresses"] = [serialize_ip_address(address) for address in addresses]
    return jsonify(detail)


@api_bp.route("/ip-batches/<int:batch_id>/config.txt", methods=["GET"])
@require_auth
def ip_batch_config_download(batch_id):
    batch = IpBatch.query.get(batch_id)
    if not batch:
        return jsonify(error="Lote de IPs não encontrado."), 404

    addresses = active_ip_addresses_for_batch(batch.id)
    filename = f"ips-{safe_filename(batch.name)}-routes.txt"
    body = build_ip_route_config(addresses)
    return Response(
        body, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@api_bp.route("/ip-batches/<int:batch_id>/files/<int:file_id>", methods=["GET"])
@require_auth
def ip_batch_file_view(batch_id, file_id):
    batch_file = IpBatchFile.query.filter_by(id=file_id, batch_id=batch_id).first()
    if not batch_file:
        return jsonify(error="Arquivo não encontrado."), 404
    return send_stored_file(batch_file, as_attachment=False)


@api_bp.route("/ip-batches/<int:batch_id>/files/<int:file_id>/download", methods=["GET"])
@require_auth
def ip_batch_file_download(batch_id, file_id):
    batch_file = IpBatchFile.query.filter_by(id=file_id, batch_id=batch_id).first()
    if not batch_file:
        return jsonify(error="Arquivo não encontrado."), 404
    return send_stored_file(batch_file, as_attachment=True)


@api_bp.route("/deploy/ip-routes", methods=["POST"])
@require_auth
def deploy_ip_routes():
    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") is not True:
        return (
            jsonify(
                error='Ação real de publicação no roteador. Envie {"confirm": true} no corpo '
                "da requisição para confirmar."
            ),
            400,
        )

    actor_user = current_actor_user()
    addresses = active_ip_addresses_for_router()
    config = build_ip_route_config(addresses)

    if not acquire_publish_lock(owner=actor_user.username if actor_user else "api"):
        return jsonify(error=publish_lock_message()), 409

    deployment = Deployment(
        deployment_type="router",
        user_id=actor_user.id if actor_user else None,
        status="running",
        domain_count=0,
        ip_count=len(addresses),
    )
    db.session.add(deployment)
    db.session.commit()

    try:
        message = publish_ip_routes(
            config, configured_router_targets(), configured_strict_host_key_checking()
        )
        deployment.status = "success"
        deployment.message = message
        db.session.commit()
        return jsonify(
            status="success", message=message, ip_count=len(addresses), deployment_id=deployment.id
        )
    except Exception as exc:
        deployment.status = "error"
        deployment.message = str(exc)
        db.session.commit()
        return jsonify(status="error", error=str(exc), message=str(exc), deployment_id=deployment.id), 502
    finally:
        release_publish_lock()


@api_bp.route("/deployments", methods=["GET"])
@require_auth
def list_deployments():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), MAX_PER_PAGE)
    deployment_type = request.args.get("deployment_type", "", type=str).strip()
    status = request.args.get("status", "", type=str).strip()

    query = Deployment.query
    if deployment_type:
        query = query.filter(Deployment.deployment_type == deployment_type)
    if status:
        query = query.filter(Deployment.status == status)

    pagination = query.order_by(Deployment.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    users_by_id = load_users_by_id(
        {deployment.user_id for deployment in pagination.items if deployment.user_id}
    )

    items = []
    for deployment in pagination.items:
        item = serialize_deployment(deployment)
        creator = users_by_id.get(deployment.user_id)
        item["created_by_username"] = creator.username if creator else None
        items.append(item)

    return jsonify(
        items=items,
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
        pages=pagination.pages,
    )


@api_bp.route("/deployments/<int:deployment_id>", methods=["GET"])
@require_auth
def get_deployment(deployment_id):
    deployment = Deployment.query.get(deployment_id)
    if not deployment:
        return jsonify(error="Publicação não encontrada."), 404
    return jsonify(serialize_deployment(deployment))


@api_bp.route("/deploy/rpz", methods=["POST"])
@require_auth
def deploy_rpz():
    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") is not True:
        return (
            jsonify(
                error='Ação real de publicação no BIND. Envie {"confirm": true} no corpo '
                "da requisição para confirmar."
            ),
            400,
        )

    actor_user = current_actor_user()

    names = active_domain_names_for_rpz()
    zone = build_rpz_zone(names, configured_rpz_nameserver())

    if not acquire_publish_lock(owner=actor_user.username if actor_user else "api"):
        return jsonify(error=publish_lock_message()), 409

    deployment = Deployment(
        deployment_type="rpz",
        user_id=actor_user.id if actor_user else None,
        status="running",
        domain_count=len(names),
        ip_count=0,
    )
    db.session.add(deployment)
    db.session.commit()

    try:
        message = publish_zone(
            zone, configured_bind_servers(), configured_strict_host_key_checking()
        )
        deployment.status = "success"
        deployment.message = message
        db.session.commit()
        return jsonify(
            status="success",
            message=message,
            domain_count=len(names),
            deployment_id=deployment.id,
        )
    except Exception as exc:
        deployment.status = "error"
        deployment.message = str(exc)
        db.session.commit()
        return (
            jsonify(status="error", error=str(exc), message=str(exc), deployment_id=deployment.id),
            502,
        )
    finally:
        release_publish_lock()


def list_whitelist_entries(model, order_column, serializer):
    entries = model.query.order_by(order_column.asc()).all()
    return jsonify(items=[serializer(entry) for entry in entries])


def create_whitelist_entry(model, value_column, value, reason, serializer, invalid_error, conflict_error):
    if not value:
        return jsonify(error=invalid_error), 400
    if model.query.filter(value_column == value).first():
        return jsonify(error=conflict_error), 409

    actor_user = current_actor_user()
    entry = model(
        **{value_column.key: value}, reason=reason, created_by_user_id=actor_user.id if actor_user else None
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify(serializer(entry)), 201


def delete_whitelist_entry(model, entry_id, not_found_error):
    entry = model.query.get(entry_id)
    if not entry:
        return jsonify(error=not_found_error), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify(status="deleted")


@api_bp.route("/whitelist/domains", methods=["GET"])
@require_auth
def list_whitelist_domains():
    return list_whitelist_entries(WhitelistDomain, WhitelistDomain.name, serialize_whitelist_domain)


@api_bp.route("/whitelist/domains", methods=["POST"])
@require_auth
def create_whitelist_domain():
    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or "").strip() or None
    name = normalize_domain((payload.get("name") or "").strip())
    return create_whitelist_entry(
        WhitelistDomain,
        WhitelistDomain.name,
        name,
        reason,
        serialize_whitelist_domain,
        invalid_error="Informe um domínio válido.",
        conflict_error="Este domínio já está na whitelist.",
    )


@api_bp.route("/whitelist/domains/<int:entry_id>", methods=["DELETE"])
@require_auth
def delete_whitelist_domain(entry_id):
    return delete_whitelist_entry(WhitelistDomain, entry_id, "Domínio não encontrado na whitelist.")


@api_bp.route("/whitelist/ips", methods=["GET"])
@require_auth
def list_whitelist_ips():
    return list_whitelist_entries(WhitelistIp, WhitelistIp.address, serialize_whitelist_ip)


@api_bp.route("/whitelist/ips", methods=["POST"])
@require_auth
def create_whitelist_ip():
    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or "").strip() or None
    address = normalize_ip_address((payload.get("address") or "").strip())
    return create_whitelist_entry(
        WhitelistIp,
        WhitelistIp.address,
        address,
        reason,
        serialize_whitelist_ip,
        invalid_error="Informe um IP válido.",
        conflict_error="Este IP já está na whitelist.",
    )


@api_bp.route("/whitelist/ips/<int:entry_id>", methods=["DELETE"])
@require_auth
def delete_whitelist_ip(entry_id):
    return delete_whitelist_entry(WhitelistIp, entry_id, "IP não encontrado na whitelist.")


def serialize_user(user):
    return {
        "id": user.id,
        "username": user.username,
        "active": user.active,
        "abuse_access": bool(user.abuse_access),
        "created_at": iso_utc(user.created_at),
    }


@api_bp.route("/users", methods=["GET"])
@require_auth
def list_users():
    users = User.query.order_by(User.username.asc()).all()
    return jsonify(items=[serialize_user(user) for user in users])


@api_bp.route("/users", methods=["POST"])
@require_auth
def create_user():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if not username:
        return jsonify(error="Informe o usuário."), 400
    if not password:
        return jsonify(error="Informe a senha."), 400
    if User.query.filter_by(username=username).first():
        return jsonify(error="Já existe um usuário com este nome."), 409

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify(serialize_user(user)), 201


@api_bp.route("/users/<int:user_id>/password", methods=["POST"])
@require_auth
def update_user_password(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify(error="Usuário não encontrado."), 404

    # Senha de quem acessa dados pessoais do módulo de abuse só é trocada pelo
    # próprio usuário ou por outro com o mesmo acesso.
    actor_user = current_actor_user()
    if user.abuse_access and not (
        actor_user and (actor_user.id == user.id or actor_user.abuse_access)
    ):
        return jsonify(
            error="Só um usuário com acesso ao módulo de abuse pode trocar a senha deste usuário."
        ), 403

    payload = request.get_json(silent=True) or {}
    password = payload.get("password") or ""
    if not password:
        return jsonify(error="Informe a nova senha."), 400

    user.set_password(password)
    db.session.commit()
    return jsonify(status="password_updated")


@api_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@require_auth
def toggle_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify(error="Usuário não encontrado."), 404

    actor_user = current_actor_user()
    if actor_user and actor_user.id == user.id:
        return jsonify(error="Não é possível desativar o usuário autenticado."), 400
    if user.active and User.query.filter_by(active=True).count() <= 1:
        return jsonify(error="Não é possível desativar o último usuário ativo."), 400
    if (
        user.active
        and user.abuse_access
        and User.query.filter_by(active=True, abuse_access=True).count() <= 1
    ):
        return jsonify(
            error="Não é possível desativar o último usuário com acesso ao módulo de abuse."
        ), 400

    user.active = not user.active
    db.session.commit()
    return jsonify(serialize_user(user))


def get_or_create_company_settings():
    settings = CompanySettings.query.order_by(CompanySettings.id.asc()).first()
    if not settings:
        settings = CompanySettings()
        db.session.add(settings)
        db.session.commit()
    return settings


def serialize_company_settings(settings):
    return {
        "company_name": settings.company_name,
        "cnpj": settings.cnpj,
        "asn": settings.asn,
        "address": settings.address,
        "address_street": settings.address_street,
        "address_number": settings.address_number,
        "address_complement": settings.address_complement,
        "address_neighborhood": settings.address_neighborhood,
        "address_city": settings.address_city,
        "address_state": settings.address_state,
        "address_zip": settings.address_zip,
        "anatel_responsible_name": settings.anatel_responsible_name,
        "anatel_responsible_phone": settings.anatel_responsible_phone,
        "anatel_responsible_email": settings.anatel_responsible_email,
        "duty_phone": settings.duty_phone,
        "duty_email": settings.duty_email,
        "updated_at": iso_utc(settings.updated_at),
    }


@api_bp.route("/company-settings", methods=["GET"])
@require_auth
def get_company_settings():
    return jsonify(serialize_company_settings(get_or_create_company_settings()))


@api_bp.route("/company-settings", methods=["PUT"])
@require_auth
def update_company_settings():
    settings = get_or_create_company_settings()
    payload = request.get_json(silent=True) or {}

    settings.company_name = (payload.get("company_name") or "").strip()
    settings.cnpj = (payload.get("cnpj") or "").strip()
    settings.asn = (payload.get("asn") or "").strip()
    settings.address_street = (payload.get("address_street") or "").strip()
    settings.address_number = (payload.get("address_number") or "").strip()
    settings.address_complement = (payload.get("address_complement") or "").strip()
    settings.address_neighborhood = (payload.get("address_neighborhood") or "").strip()
    settings.address_city = (payload.get("address_city") or "").strip()
    settings.address_state = (payload.get("address_state") or "").strip().upper()
    settings.address_zip = (payload.get("address_zip") or "").strip()
    settings.anatel_responsible_name = (payload.get("anatel_responsible_name") or "").strip()
    settings.anatel_responsible_phone = (payload.get("anatel_responsible_phone") or "").strip()
    settings.anatel_responsible_email = (payload.get("anatel_responsible_email") or "").strip()
    settings.duty_phone = (payload.get("duty_phone") or "").strip()
    settings.duty_email = (payload.get("duty_email") or "").strip()
    db.session.commit()

    return jsonify(serialize_company_settings(settings))


def get_or_create_parameter_settings():
    settings = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    if not settings:
        settings = ParameterSettings()
        db.session.add(settings)
        db.session.commit()
    return settings


def serialize_parameter_settings(settings):
    return {
        "dns_primary": settings.dns_primary or "",
        "dns_secondary": settings.dns_secondary or "",
        "extra_dns_servers": load_json_list(settings.extra_dns_servers),
        "publish_routers": public_targets(load_targets(settings.publish_routers, "router")),
        "router_command_ipv4": settings.router_command_ipv4 or DEFAULT_ROUTER_COMMAND_IPV4,
        "router_command_ipv6": settings.router_command_ipv6 or DEFAULT_ROUTER_COMMAND_IPV6,
        "rpz_servers": public_targets(load_targets(settings.rpz_servers, "bind")),
        "rpz_nameserver": settings.rpz_nameserver or "",
        "ssh_strict_host_key_checking": settings.ssh_strict_host_key_checking is not False,
        "smtp_host": settings.smtp_host or "",
        "smtp_port": settings.smtp_port or "",
        "smtp_security": settings.smtp_security or "starttls",
        "smtp_user": settings.smtp_user or "",
        "smtp_password_set": bool(settings.smtp_password),
        "smtp_from_email": settings.smtp_from_email or "",
        "smtp_from_name": settings.smtp_from_name or "",
        "email_signature": settings.email_signature or "",
        "imap_host": settings.imap_host or "",
        "imap_port": settings.imap_port or "",
        "imap_user": settings.imap_user or "",
        "imap_password_set": bool(settings.imap_password),
        "imap_mailbox": settings.imap_mailbox or "",
        "updated_at": iso_utc(settings.updated_at),
    }


def normalize_json_list_payload(value):
    if not value:
        return json.dumps([])
    if isinstance(value, str):
        value = [value]
    return json.dumps([str(item).strip() for item in value if str(item).strip()])


def apply_smtp_payload(settings, payload):
    """Valida e aplica os campos de SMTP (sem commit). Levanta ValueError."""
    if "smtp_host" in payload:
        settings.smtp_host = str(payload["smtp_host"] or "").strip() or None
    if "smtp_port" in payload:
        raw_port = str(payload["smtp_port"] or "").strip()
        try:
            port = int(raw_port) if raw_port else None
        except ValueError as exc:
            raise ValueError("Porta SMTP deve ser um número inteiro.") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Porta SMTP deve estar entre 1 e 65535.")
        settings.smtp_port = port
    if "smtp_security" in payload:
        security = str(payload["smtp_security"] or "starttls").strip()
        if security not in SMTP_SECURITIES:
            raise ValueError("Segurança SMTP inválida: use starttls, ssl ou none.")
        settings.smtp_security = security
    for key in ("smtp_user", "smtp_from_name"):
        if key in payload:
            setattr(settings, key, str(payload[key] or "").strip() or None)
    if "smtp_from_email" in payload:
        from_email = str(payload["smtp_from_email"] or "").strip()
        if from_email and not parse_recipients(from_email)[0]:
            raise ValueError("E-mail remetente inválido.")
        settings.smtp_from_email = from_email or None
    if "email_signature" in payload:
        settings.email_signature = str(payload["email_signature"] or "").strip() or None
    # Senha só muda quando enviada; "clear_smtp_password" apaga a atual.
    if payload.get("smtp_password"):
        settings.smtp_password = str(payload["smtp_password"])
    elif payload.get("clear_smtp_password"):
        settings.smtp_password = None


@api_bp.route("/parameter-settings/smtp-test", methods=["POST"])
@require_auth
def test_smtp_settings():
    """Testa a conexão com os dados do formulário (ainda não salvos), sem gravar nada."""
    settings = get_or_create_parameter_settings()
    try:
        apply_smtp_payload(settings, request.get_json(silent=True) or {})
        problem = smtp_config_problem(settings)
        if problem:
            raise ValueError(problem)
        test_smtp_connection(settings)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Falha na conexão: {describe_mail_error(exc)}"), 502
    finally:
        db.session.rollback()
    return jsonify(message="Conexão e autenticação SMTP OK.")


def apply_imap_payload(settings, payload):
    """Valida e aplica os campos da caixa de abuse (sem commit). Levanta ValueError."""
    if "imap_host" in payload:
        settings.imap_host = str(payload["imap_host"] or "").strip()
    if "imap_port" in payload:
        raw_port = str(payload["imap_port"] or "").strip()
        try:
            port = int(raw_port) if raw_port else None
        except ValueError as exc:
            raise ValueError("Porta IMAP deve ser um número inteiro.") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Porta IMAP deve estar entre 1 e 65535.")
        settings.imap_port = port
    for key in ("imap_user", "imap_mailbox"):
        if key in payload:
            setattr(settings, key, str(payload[key] or "").strip() or None)
    # Senha só muda quando enviada; "clear_imap_password" apaga a atual.
    if payload.get("imap_password"):
        settings.imap_password = str(payload["imap_password"])
    elif payload.get("clear_imap_password"):
        settings.imap_password = None


@api_bp.route("/parameter-settings/imap-test", methods=["POST"])
@require_auth
def test_imap_settings():
    """Testa login e abertura da caixa (somente leitura) com os dados do formulário,
    ainda não salvos, sem gravar nada."""
    settings = get_or_create_parameter_settings()
    connection = None
    try:
        apply_imap_payload(settings, request.get_json(silent=True) or {})
        config = ImapConfig.from_settings(settings)
        if config is None:
            raise ValueError("Servidor IMAP não configurado.")
        connection = imap_connect(config)
        ReadOnlyMailbox(connection, config.mailbox)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Falha na conexão: {exc}"), 502
    finally:
        db.session.rollback()
        if connection is not None:
            try:
                connection.logout()
            except Exception:
                pass
    return jsonify(message="Conexão IMAP OK: login feito e caixa aberta em modo somente leitura.")


@api_bp.route("/parameter-settings", methods=["GET"])
@require_auth
def get_parameter_settings():
    return jsonify(serialize_parameter_settings(get_or_create_parameter_settings()))


@api_bp.route("/parameter-settings", methods=["PUT"])
@require_auth
def update_parameter_settings():
    settings = get_or_create_parameter_settings()
    payload = request.get_json(silent=True) or {}

    router_command_ipv4 = (payload.get("router_command_ipv4") or "").strip()
    router_command_ipv6 = (payload.get("router_command_ipv6") or "").strip()
    template_error = validate_router_command_template(
        router_command_ipv4, "IPv4"
    ) or validate_router_command_template(router_command_ipv6, "IPv6")
    if template_error:
        return jsonify(error=template_error), 400

    rpz_nameserver = (payload.get("rpz_nameserver") or "").strip().rstrip(".")
    if rpz_nameserver and not normalize_domain(rpz_nameserver):
        return jsonify(error="Servidor de nomes da zona RPZ inválido: use um nome como ns1.exemplo.com.br."), 400

    try:
        publish_routers = merge_targets(
            payload.get("publish_routers"), load_targets(settings.publish_routers, "router"), "router"
        )
        rpz_servers = merge_targets(
            payload.get("rpz_servers"), load_targets(settings.rpz_servers, "bind"), "bind"
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    try:
        apply_smtp_payload(settings, payload)
        apply_imap_payload(settings, payload)
    except ValueError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400

    settings.dns_primary = (payload.get("dns_primary") or "").strip()
    settings.dns_secondary = (payload.get("dns_secondary") or "").strip()
    settings.extra_dns_servers = normalize_json_list_payload(payload.get("extra_dns_servers"))
    settings.publish_routers = dump_targets(publish_routers)
    settings.rpz_servers = dump_targets(rpz_servers)
    settings.rpz_nameserver = rpz_nameserver or None
    if "ssh_strict_host_key_checking" in payload:
        settings.ssh_strict_host_key_checking = bool(payload["ssh_strict_host_key_checking"])
    settings.router_command_ipv4 = router_command_ipv4
    settings.router_command_ipv6 = router_command_ipv6
    db.session.commit()

    return jsonify(serialize_parameter_settings(settings))


def offices_by_month(today, months=12):
    """Quantidade de ofícios por mês (data de expedição, ou de cadastro) nos últimos meses."""
    keys = []
    year, month = today.year, today.month
    for _ in range(months):
        keys.append((year, month))
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    keys.reverse()

    counts = dict.fromkeys(keys, 0)
    rows = db.session.query(UploadBatch.expedition_date, UploadBatch.created_at).all()
    for expedition_date, created_at in rows:
        reference = expedition_date or (created_at.date() if created_at else None)
        if reference is None:
            continue
        key = (reference.year, reference.month)
        if key in counts:
            counts[key] += 1

    return [{"month": f"{year:04d}-{month:02d}", "count": counts[(year, month)]} for year, month in keys]


@api_bp.route("/dashboard", methods=["GET"])
@require_auth
def dashboard_metrics():
    today = date.today()
    batches = (
        UploadBatch.query.order_by(
            UploadBatch.expedition_date.is_(None),
            UploadBatch.expedition_date.desc(),
            UploadBatch.created_at.desc(),
        )
        .limit(10)
        .all()
    )
    deployments = Deployment.query.order_by(Deployment.created_at.desc()).limit(5).all()
    users_by_id = load_users_by_id(
        {batch.created_by_user_id for batch in batches if batch.created_by_user_id}
    )

    return jsonify(
        total_domains=Domain.query.count(),
        active_domains=Domain.query.filter_by(active=True).count(),
        removable_domains=removable_domain_count(),
        total_ips=IpAddress.query.count(),
        active_ips=IpAddress.query.filter_by(active=True).count(),
        ipv4_count=IpAddress.query.filter_by(version=4).count(),
        ipv6_count=IpAddress.query.filter_by(version=6).count(),
        removable_ips=removable_ip_count(),
        recent_offices=[
            {
                **serialize_office(batch),
                "ip_count": len(ip_addresses_for_office(batch)),
                "has_expired_items": office_has_expired_items(batch, today),
                "created_by_username": (
                    users_by_id[batch.created_by_user_id].username
                    if batch.created_by_user_id in users_by_id
                    else None
                ),
            }
            for batch in batches
        ],
        recent_deployments=[serialize_deployment(deployment) for deployment in deployments],
        offices_by_month=offices_by_month(today),
    )


@api_bp.route("/communications-config", methods=["GET"])
@require_auth
def communications_config():
    company = CompanySettings.query.order_by(CompanySettings.id.asc()).first()
    parameters = ParameterSettings.query.order_by(ParameterSettings.id.asc()).first()
    return jsonify(build_communication_config(company, parameters))


@api_bp.route("/backup/database", methods=["GET"])
@require_auth
def backup_database_download():
    try:
        data = build_database_backup()
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 500

    filename = backup_filename("backup-banco", "sql")
    return Response(
        data,
        mimetype="application/sql",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@api_bp.route("/backup/files", methods=["GET"])
@require_auth
def backup_files_download():
    try:
        data = build_files_backup()
    except OSError as exc:
        return jsonify(error=f"Não foi possível gerar o backup dos arquivos: {exc}"), 500

    filename = backup_filename("backup-arquivos", "zip")
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def perform_restore(deployment_type, restore_fn, invalid_file_error):
    confirm_phrase = (request.form.get("confirm_phrase") or "").strip()
    if confirm_phrase != RESTORE_CONFIRM_PHRASE:
        return (
            jsonify(
                error=f'Confirmação inválida. Digite exatamente "{RESTORE_CONFIRM_PHRASE}" para continuar.'
            ),
            400,
        )

    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify(error=invalid_file_error), 400

    actor_user = current_actor_user()
    actor_user_id = actor_user.id if actor_user else None
    if not acquire_publish_lock(owner=actor_user.username if actor_user else "api"):
        return jsonify(error=publish_lock_message()), 409

    deployment = Deployment(
        deployment_type=deployment_type,
        user_id=actor_user_id,
        status="running",
        domain_count=0,
        ip_count=0,
    )
    db.session.add(deployment)
    db.session.commit()
    deployment_id = deployment.id
    file_bytes = file.read()

    # Reading deployment.id right after commit() re-opens an implicit transaction on this
    # connection (attributes expire on commit by default). If left open, MySQL's metadata
    # lock for the DROP/CREATE TABLE statements a database restore runs (via a separate
    # `mysql` subprocess connection) waits on it -- for up to lock_wait_timeout, which
    # defaults to a year. Close the session so the connection goes back to the pool clean.
    db.session.close()

    try:
        restore_fn(file_bytes)
        status, message = "success", "Restauração concluída."
    except Exception as exc:
        # Captura qualquer falha, não só RuntimeError -- um erro inesperado (ex.: OSError do
        # filesystem) não pode deixar o registro preso em "running" nem o lock sem liberar.
        current_app.logger.exception("Falha ao restaurar %s", deployment_type)
        status, message = "error", str(exc) or f"{type(exc).__name__} inesperado durante a restauração."

    deployment_id = record_restore_outcome(deployment_id, deployment_type, actor_user_id, status, message)
    release_publish_lock()

    if status == "error":
        return jsonify(status="error", error=message, deployment_id=deployment_id), 502
    return jsonify(status="success", deployment_id=deployment_id)


def record_restore_outcome(deployment_id, deployment_type, user_id, status, message):
    # Restaurar o banco apaga e recria as próprias tabelas de controle (deployment,
    # publication_lock) como parte do dump, então a linha "running" criada antes da
    # restauração pode não existir mais. Descarta a sessão (que pode estar presa a objetos
    # cujas linhas sumiram) e atualiza por id numa sessão nova; se a linha não existir mais,
    # cria uma nova em vez de tentar atualizar o que já era.
    db.session.remove()
    deployment = Deployment.query.get(deployment_id)
    if deployment is None:
        deployment = Deployment(
            deployment_type=deployment_type, user_id=user_id, domain_count=0, ip_count=0
        )
        db.session.add(deployment)
    deployment.status = status
    deployment.message = message
    db.session.commit()
    return deployment.id


@api_bp.route("/backup/database/restore", methods=["POST"])
@require_auth
def backup_database_restore():
    return perform_restore("restore-database", restore_database, "Selecione o arquivo .sql do backup.")


@api_bp.route("/backup/files/restore", methods=["POST"])
@require_auth
def backup_files_restore():
    return perform_restore("restore-files", restore_files, "Selecione o arquivo .zip do backup.")
