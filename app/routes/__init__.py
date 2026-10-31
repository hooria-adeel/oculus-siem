from .access import bp as access_bp
from .auth import bp as auth_bp
from .docs import bp as docs_bp
from .employees import bp as employees_bp
from .events import bp as events_bp
from .incidents import bp as incidents_bp
from .overview import bp as overview_bp

ALL_BLUEPRINTS = (auth_bp, access_bp, employees_bp, events_bp, incidents_bp, overview_bp, docs_bp)
