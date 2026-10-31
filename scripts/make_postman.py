"""Generate the Postman collection and environment from the OpenAPI spec, so they can never drift apart.

    python scripts/make_postman.py            # writes docs/postman/*.json
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.openapi import build_spec  # noqa: E402

OUT = ROOT / "docs" / "postman"
HTTP = ("get", "post", "patch", "put", "delete")
TAG_ORDER = ["Auth", "Workspace", "Console", "Admin"]

SAVE_TOKEN = [
    'pm.test("Signed in", () => pm.response.to.have.status(200));',
    'const body = pm.response.json();',
    'pm.test("Response carries a token", () => pm.expect(body.token).to.be.a("string"));',
    'pm.environment.set("token", body.token);',
]


def js(*lines):
    return {"listen": "test", "script": {"type": "text/javascript", "exec": list(lines)}}


def expected_status(op):
    return next((int(c) for c in op["responses"] if c.startswith("2")), 200)


def request_item(path, method, op):
    url_path = [seg if not seg.startswith("{") else "{{incidentId}}" for seg in path.strip("/").split("/")]
    query = [{"key": p["name"], "value": str(p.get("example", p["schema"].get("default", ""))), "disabled": p["name"] != "limit",
              "description": p.get("description", "")} for p in op.get("parameters", []) if p["in"] == "query"]
    raw = "{{baseUrl}}/" + "/".join(url_path)
    item = {"name": op["summary"], "request": {
        "method": method.upper(), "header": [], "description": op.get("description", ""),
        "url": {"raw": raw + ("?" + "&".join(f"{q['key']}={q['value']}" for q in query if not q["disabled"]) if any(not q["disabled"] for q in query) else ""),
                "host": ["{{baseUrl}}"], "path": url_path, "query": query}}}
    if op.get("security") == []:
        item["request"]["auth"] = {"type": "noauth"}
    body = op.get("requestBody")
    if body:
        example = dict(body["content"]["application/json"]["example"])
        if op["operationId"] == "addEmployee":      # unique on every run, so the request can be replayed
            example.update(username="new.hire.{{$timestamp}}@oculus.com", employeeId="OC-{{$randomInt}}")
        item["request"]["header"].append({"key": "Content-Type", "value": "application/json"})
        item["request"]["body"] = {"mode": "raw", "raw": json.dumps(example, indent=2), "options": {"raw": {"language": "json"}}}
    tests = [f'pm.test("Status is {expected_status(op)}", () => pm.response.to.have.status({expected_status(op)}));']
    if op["operationId"] == "listIncidents":
        tests += ['const list = pm.response.json();', 'if (list.length) pm.environment.set("incidentId", list[0].id);']
    if op["operationId"] == "login":
        item["name"] = "Sign in (custom body)"
        tests = SAVE_TOKEN
    item["event"] = [js(*tests)]
    return item


def login_as(name, user_var, pass_var, desc):
    return {"name": name, "event": [js(*SAVE_TOKEN)], "request": {
        "method": "POST", "header": [{"key": "Content-Type", "value": "application/json"}], "auth": {"type": "noauth"}, "description": desc,
        "url": {"raw": "{{baseUrl}}/api/login", "host": ["{{baseUrl}}"], "path": ["api", "login"]},
        "body": {"mode": "raw", "raw": json.dumps({"username": "{{%s}}" % user_var, "password": "{{%s}}" % pass_var}, indent=2),
                 "options": {"raw": {"language": "json"}}}}}


def build():
    spec = build_spec()
    folders = {t: [] for t in TAG_ORDER}
    for path, item in spec["paths"].items():
        for method in HTTP:
            if method in item:
                op = item[method]
                folders[op["tags"][0]].append(request_item(path, method, op))
    auth = folders["Auth"]
    auth.sort(key=lambda i: i["name"] == "Sign out")        # sign-out last: the rest of the run still needs the session
    auth[:0] = [
        login_as("Sign in as analyst", "adminUser", "adminPassword", "Run this first for the Console and Admin folders. Saves the JWT to {{token}}."),
        login_as("Sign in as employee", "employeeUser", "employeePassword", "Run this first for the Workspace folder. Saves the JWT to {{token}}."),
    ]
    desc = {t["name"]: t.get("description", "") for t in spec["tags"]}
    return {
        "info": {"name": "Oculus API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                 "description": spec["info"]["description"]},
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}", "type": "string"}]},
        "item": [{"name": t, "description": desc.get(t, ""), "item": folders[t]} for t in TAG_ORDER],
    }, {
        "name": "Oculus (local)", "_postman_variable_scope": "environment",
        "values": [{"key": k, "value": v, "enabled": True, "type": "secret" if k == "token" or "assword" in k else "default"} for k, v in [
            ("baseUrl", "http://localhost:5000"), ("token", ""), ("incidentId", "1"),
            ("adminUser", "imran.shah@oculus.com"), ("adminPassword", "Oculus#Admin26"),
            ("employeeUser", "ahmed.khan@oculus.com"), ("employeePassword", "Oculus#Demo26")]],
    }


def render():
    collection, environment = build()
    return (json.dumps(collection, indent=2) + "\n", json.dumps(environment, indent=2) + "\n")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    col, env = render()
    (OUT / "oculus.postman_collection.json").write_text(col)
    (OUT / "oculus.postman_environment.json").write_text(env)
    print(f"wrote {OUT / 'oculus.postman_collection.json'}")
