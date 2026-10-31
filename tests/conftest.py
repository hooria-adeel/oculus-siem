import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import Resource, ResourcePermission, User
from app.services.auth import hash_password

PASSWORD = "S3cret!pass"
ADMIN = "admin@oculus.com"
IT = "it.user@oculus.com"
HR = "hr.user@oculus.com"


class Api:
    """Thin test client wrapper: tracks the CSRF token like the real frontend does."""

    def __init__(self, app):
        self.app = app
        self.client = app.test_client()
        self.csrf = None
        self.token = None

    def login(self, username, password=PASSWORD, ip="10.0.0.1"):
        r = self.client.post(
            "/api/login",
            json={"username": username, "password": password},
            environ_overrides={"REMOTE_ADDR": ip},
        )
        if r.status_code == 200:
            self.token = r.get_json()["token"]
            cookie = self.client.get_cookie("oculus_csrf")
            self.csrf = cookie.value if cookie else None
        return r

    def request(self, method, url, csrf=True, ip="10.0.0.1", **kw):
        headers = dict(kw.pop("headers", {}))
        if csrf and self.csrf and method.upper() not in ("GET", "HEAD", "OPTIONS"):
            headers["X-CSRF-Token"] = self.csrf
        return self.client.open(url, method=method, headers=headers,
                                environ_overrides={"REMOTE_ADDR": ip}, **kw)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, json=None, **kw):
        return self.request("POST", url, json=json, **kw)


def _user(username, role, emp_id, risk=0):
    return User(
        username=username,
        password_hash=hash_password(PASSWORD),
        full_name=username.split("@")[0].replace(".", " ").title(),
        employee_id=emp_id,
        role=role,
        risk_score=risk,
    )


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        db.session.add_all([
            _user(ADMIN, "Admin", "OC-9001"),
            _user(IT, "IT", "OC-1001"),
            _user(HR, "HR", "OC-1002"),
        ])
        firewall = Resource(name="Firewall.config", is_honeypot=False, description="Firewall", content="rules")
        payroll = Resource(name="Payroll.xlsx", is_honeypot=False, description="Payroll", content="salaries")
        trap = Resource(name="Admin_Passwords.txt", is_honeypot=True, description="Totally real", content="x")
        db.session.add_all([firewall, payroll, trap])
        db.session.flush()
        db.session.add_all([
            ResourcePermission(resource_id=firewall.id, role="IT"),
            ResourcePermission(resource_id=payroll.id, role="HR"),
        ])
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def anon(app):
    return Api(app)


def _logged_in(app, username):
    api = Api(app)
    assert api.login(username).status_code == 200
    return api


@pytest.fixture()
def admin(app):
    return _logged_in(app, ADMIN)


@pytest.fixture()
def it(app):
    return _logged_in(app, IT)


@pytest.fixture()
def hr(app):
    return _logged_in(app, HR)


def get_user(username):
    return User.query.filter_by(username=username).one()
