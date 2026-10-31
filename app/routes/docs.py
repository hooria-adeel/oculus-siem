"""API documentation: the OpenAPI document and a self-hosted Swagger UI (no CDN, so the strict CSP stays strict)."""
from flask import Blueprint, current_app, jsonify, send_from_directory

from ..openapi import build_spec

bp = Blueprint("docs", __name__, url_prefix="/api")


@bp.get("/openapi.json")
def openapi():
    return jsonify(build_spec())


@bp.get("/docs")
def swagger_ui():
    return send_from_directory(current_app.static_folder, "api-docs.html")
