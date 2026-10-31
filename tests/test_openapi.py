"""The API description is a contract, not a brochure: it must cover every route and match what the server really returns."""
import re

import pytest
from jsonschema import Draft202012Validator

from app.openapi import build_spec

SPEC = build_spec()
HTTP = {"get", "post", "put", "patch", "delete"}


def spec_operations():
    return {(m.upper(), path) for path, item in SPEC["paths"].items() for m in item if m in HTTP}


def app_operations(app):
    ops = set()
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/") and rule.endpoint not in ("docs.openapi", "docs.swagger_ui"):
            path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", rule.rule)
            ops |= {(m, path) for m in rule.methods - {"HEAD", "OPTIONS"}}
    return ops


def check(schema_name, payload):
    """Validate a live JSON payload against a component schema from the spec."""
    v = Draft202012Validator({"$ref": f"#/components/schemas/{schema_name}", "components": SPEC["components"]})
    errors = sorted(v.iter_errors(payload), key=lambda e: list(e.path))
    assert not errors, "; ".join(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors[:5])


# ---- the document itself --------------------------------------------------------------------------------------------

def test_every_route_is_documented_and_nothing_extra(app):
    assert spec_operations() == app_operations(app)


def test_operation_ids_are_unique_and_every_operation_is_described():
    ids = [op["operationId"] for item in SPEC["paths"].values() for m, op in item.items() if m in HTTP]
    assert len(ids) == len(set(ids))
    for item in SPEC["paths"].values():
        for m, op in item.items():
            if m in HTTP:
                assert op["summary"] and op["tags"] and op["responses"]


def test_all_refs_resolve():
    text, missing = str(SPEC), []
    for name in set(re.findall(r"#/components/schemas/(\w+)", text)):
        if name not in SPEC["components"]["schemas"]:
            missing.append(name)
    assert not missing


def test_schemas_are_valid_json_schema():
    for name, schema in SPEC["components"]["schemas"].items():
        Draft202012Validator.check_schema(schema)


def test_protected_operations_declare_401_and_admin_ones_declare_403():
    for path, item in SPEC["paths"].items():
        for m, op in item.items():
            if m not in HTTP or op.get("security") == []:
                continue
            assert "401" in op["responses"], (m, path)
            if op.get("x-admin-only"):
                assert "403" in op["responses"], (m, path)


def test_request_examples_validate_against_their_schemas():
    for item in SPEC["paths"].values():
        for m, op in item.items():
            body = op.get("requestBody") if m in HTTP else None
            if body:
                media = body["content"]["application/json"]
                check(media["schema"]["$ref"].rsplit("/", 1)[1], media["example"])


def test_docs_endpoints_are_public_and_swagger_page_is_served(anon):
    assert anon.get("/api/openapi.json").get_json()["openapi"].startswith("3.1")
    page = anon.get("/api/docs")
    assert page.status_code == 200 and b"swagger" in page.data.lower()


# ---- live responses match the schemas -------------------------------------------------------------------------------

def test_auth_responses_match(anon, it):
    check("LoginResponse", anon.login("it.user@oculus.com").get_json())
    check("User", it.get("/api/me").get_json())
    check("Error", anon.post("/api/login", json={"username": "it.user@oculus.com", "password": "wrong"}).get_json())


def test_workspace_responses_match(it):
    check("AccessResult", it.post("/api/access", json={"resourceName": "Firewall.config"}).get_json())
    check("AccessResult", it.post("/api/access", json={"resourceName": "Payroll.xlsx"}).get_json())
    check("AccessResult", it.post("/api/access", json={"resourceName": "Admin_Passwords.txt"}).get_json())
    check("AccessResult", it.post("/api/access", json={"resourceName": "nope"}).get_json())
    for r in it.get("/api/resources").get_json():
        check("Resource", r)
    recent = it.get("/api/my/recent").get_json()
    assert recent
    for r in recent:
        check("RecentFile", r)


@pytest.fixture()
def busy(admin, it):
    for _ in range(4):
        it.post("/api/access", json={"resourceName": "Payroll.xlsx"})
    it.post("/api/access", json={"resourceName": "Admin_Passwords.txt"})
    return admin


def test_console_responses_match(busy):
    check("Overview", busy.get("/api/overview?hours=24").get_json())
    check("Overview", busy.get("/api/overview?hours=1").get_json())
    events = busy.get("/api/events?limit=50").get_json()
    check("EventList", events)
    assert events["events"], "need data for the contract check to mean anything"
    incidents = busy.get("/api/incidents").get_json()
    assert incidents
    for i in incidents:
        check("Incident", i)
    check("Timeline", busy.get(f"/api/incidents/{incidents[0]['id']}/timeline").get_json())
    for r in busy.get("/api/rules").get_json():
        check("Rule", r)
    for h in busy.get("/api/honeypots").get_json():
        check("Honeypot", h)


def test_incident_writes_match(busy):
    iid = busy.get("/api/incidents").get_json()[0]["id"]
    check("IncidentResult", busy.request("PATCH", f"/api/incidents/{iid}", json={"status": "investigating", "note": "on it"}).get_json())
    check("IncidentResult", busy.post(f"/api/incidents/{iid}/notes", json={"note": "context"}).get_json())
    check("Timeline", busy.get(f"/api/incidents/{iid}/timeline").get_json())      # now with analyst activity in it
    check("Error", busy.get("/api/incidents/999999").get_json())


def test_employee_responses_match(admin):
    for e in admin.get("/api/employees").get_json():
        check("Employee", e)
    body = {"fullName": "New Hire", "username": "new@oculus.com", "password": "Passw0rd!2026", "employeeId": "OC-2000", "role": "HR"}
    created = admin.post("/api/employees", json=body).get_json()
    assert set(created) == {"success", "user"}
    check("Employee", created["user"])
    check("Error", admin.post("/api/employees", json=body).get_json())


def test_demo_accounts_response_matches(app, anon):
    app.config["DEMO_MODE"] = True
    check("DemoAccounts", anon.get("/api/demo-accounts").get_json())


# ---- Postman is generated from the spec ------------------------------------------------------------------------------

def test_committed_postman_files_are_in_sync_with_the_spec():
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "scripts"))
    import make_postman
    collection, environment = make_postman.render()
    out = root / "docs" / "postman"
    assert (out / "oculus.postman_collection.json").read_text() == collection, "run: python scripts/make_postman.py"
    assert (out / "oculus.postman_environment.json").read_text() == environment, "run: python scripts/make_postman.py"


def test_postman_collection_covers_every_operation():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    col = json.loads((root / "docs" / "postman" / "oculus.postman_collection.json").read_text())
    requests = {(i["request"]["method"], "/" + "/".join(i["request"]["url"]["path"]))
                for f in col["item"] for i in f["item"]}
    for method, path in spec_operations():
        assert (method, re.sub(r"\{\w+\}", "{{incidentId}}", path)) in requests


def test_spec_passes_the_official_openapi_validator():
    from openapi_spec_validator import validate
    validate(build_spec())
