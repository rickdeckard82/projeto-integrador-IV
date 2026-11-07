from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

from . import abuse_routes, backup_routes, communication_routes, routes  # noqa: E402,F401
