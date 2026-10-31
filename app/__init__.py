from pathlib import Path

from flask import Flask, jsonify, redirect

from .config import DEFAULT_SECRET, Config
from .extensions import db, migrate
from .routes import ALL_BLUEPRINTS
from .security import add_security_headers

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def create_app(config_object=Config) -> Flask:
    """Application factory: one place that wires config, extensions and routes."""
    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",  # serve the UI from the same origin as the API
    )
    app.config.from_object(config_object)

    if not app.config["TESTING"] and not app.config["DEBUG"] and app.config["SECRET_KEY"] == DEFAULT_SECRET:
        raise RuntimeError("SECRET_KEY must be set to a strong random value outside development (see .env.example).")

    db.init_app(app)
    migrate.init_app(app, db)
    from . import models  # noqa: F401  (register tables for Alembic)
    app.after_request(add_security_headers)
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)

    from .seed import seed_command
    from .simulate import simulate_command
    app.cli.add_command(seed_command)
    app.cli.add_command(simulate_command)

    @app.get("/")
    def index():
        return redirect("/login.html")

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"success": False, "message": "Not found."}), 404

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"success": False, "message": "Internal server error."}), 500

    return app
