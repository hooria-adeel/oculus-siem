"""OpenAPI 3.1 description of the Oculus HTTP API.

Built in code (not hand-maintained YAML) so enums come straight from the models, and tests/test_openapi.py checks the
spec against the real route map and against live responses. Served at /api/openapi.json and rendered at /api/docs.
"""
from .models import ACTIVITY_KINDS, EVENT_TYPES, INCIDENT_STATUSES, OUTCOMES, ROLES, SEVERITIES

S = "#/components/schemas/"
NULLABLE_STR = {"type": ["string", "null"]}


def ref(name):
    return {"$ref": S + name}


def obj(props, required=None, desc=None, extra=True):
    out = {"type": "object", "properties": props}
    if required is None:
        required = list(props)
    out["required"] = required
    if desc:
        out["description"] = desc
    return out


def arr(item):
    return {"type": "array", "items": item}


STR, INT, BOOL = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
TS = {"type": "string", "format": "date-time", "description": "UTC, ISO 8601 with a trailing Z."}
SEV = {"type": "string", "enum": list(SEVERITIES)}

SCHEMAS = {
    "Error": obj({"success": {"const": False}, "message": STR}, desc="Every failure has this shape."),
    "User": obj({"username": STR, "fullName": STR, "employeeId": STR, "role": {"type": "string", "enum": list(ROLES)},
                 "createdAt": TS}, desc="The signed-in user. Employees never receive their own risk score."),
    "LoginResponse": obj({"success": {"const": True}, "token": {**STR, "description": "JWT (HS256). Use as a Bearer token."},
                          "user": ref("User")}),
    "LoginRequest": obj({"username": {**STR, "examples": ["imran.shah@oculus.com"]}, "password": STR}),
    "Resource": obj({"name": STR, "description": STR, "folder": STR, "sizeKb": INT, "modifiedAt": TS,
                     "category": {"type": "string", "enum": ["accessible", "restricted"],
                                  "description": "Decoy files are listed as accessible, exactly like real files."}}),
    "RecentFile": obj({"name": STR, "openedAt": TS}),
    "AccessRequest": obj({"resourceName": STR}),
    "AccessResult": obj({"authorized": BOOL, "content": NULLABLE_STR, "message": STR, "warning": NULLABLE_STR},
                        desc="Opening a decoy looks like a normal success. Security is alerted silently."),
    "Employee": obj({"username": STR, "fullName": STR, "employeeId": STR, "role": {"type": "string", "enum": list(ROLES)},
                     "createdAt": TS, "lastLoginAt": {"type": ["string", "null"], "format": "date-time"},
                     "riskScore": {"type": "integer", "minimum": 0, "maximum": 100}},
                    required=["username", "fullName", "employeeId", "role", "createdAt", "riskScore"],
                    desc="`lastLoginAt` is present on the list endpoint only."),
    "NewEmployee": obj({"fullName": STR, "username": {**STR, "format": "email"}, "password": {**STR, "minLength": 8},
                        "employeeId": STR, "role": {"type": "string", "enum": [r for r in ROLES if r != "Admin"]}}),
    "SecurityEvent": obj({"id": INT, "timestamp": TS, "eventType": {"type": "string", "enum": list(EVENT_TYPES)},
                          "outcome": {"type": "string", "enum": list(OUTCOMES)}, "severity": SEV, "username": STR,
                          "sourceIp": NULLABLE_STR, "userAgent": NULLABLE_STR, "resourceName": NULLABLE_STR,
                          "details": {"type": "object"}}),
    "EventList": obj({"events": arr(ref("SecurityEvent")), "total": {**INT, "description": "Rows matching the filters."},
                      "latestId": {**INT, "description": "Highest event id in the database; poll with since_id."}}),
    "Incident": obj({"id": INT, "ref": {**STR, "examples": ["INC-0042"]}, "title": STR, "summary": STR, "severity": SEV,
                     "status": {"type": "string", "enum": list(INCIDENT_STATUSES)}, "ruleId": {**STR, "examples": ["R-BF-001"]},
                     "mitreTactic": NULLABLE_STR, "mitreTechnique": NULLABLE_STR, "subject": STR, "sourceIp": NULLABLE_STR,
                     "riskScore": {"type": ["integer", "null"]}, "evidenceCount": INT, "openedAt": TS, "updatedAt": TS,
                     "resolvedAt": {"type": ["string", "null"], "format": "date-time"}, "resolvedBy": NULLABLE_STR,
                     "mitreTechniqueName": NULLABLE_STR}, required=["id", "ref", "title", "severity", "status", "ruleId", "subject", "openedAt"]),
    "IncidentUpdate": obj({"status": {"type": "string", "enum": list(INCIDENT_STATUSES)}, "note": STR}, required=["status"]),
    "NoteRequest": obj({"note": {**STR, "maxLength": 2000}}),
    "IncidentResult": obj({"success": {"const": True}, "incident": ref("Incident")}),
    "Activity": obj({"timestamp": TS, "kind": {"type": "string", "enum": list(ACTIVITY_KINDS)}, "message": STR,
                     "actor": {**STR, "description": "Username, or `system` for automatic entries."}}),
    "TimelineItem": obj({"kind": {"type": "string", "enum": ["event", "activity"]}, "time": TS,
                         "linked": {**BOOL, "description": "True for evidence and the activity trail; false for surrounding context events."},
                         "event": {**ref("SecurityEvent"), "description": "Present when kind is `event`."},
                         "activity": {**ref("Activity"), "description": "Present when kind is `activity`."}},
                        required=["kind", "time", "linked"]),
    "Timeline": obj({"incident": ref("Incident"), "items": arr(ref("TimelineItem")),
                     "stats": obj({"linkedEvents": INT, "contextEvents": INT, "activities": INT,
                                   "firstSeen": {"type": ["string", "null"]}, "lastSeen": {"type": ["string", "null"]}}, required=[])},
                    required=["incident", "items", "stats"]),
    "Rule": obj({"id": STR, "name": STR, "description": STR, "severity": SEV, "mitreTactic": STR, "mitreTechnique": STR,
                 "mitreTechniqueName": STR, "triggers": arr(STR), "incidents": INT, "openIncidents": INT}),
    "Honeypot": obj({"name": STR, "description": NULLABLE_STR, "hits": INT, "uniqueUsers": INT, "lastHitAt": NULLABLE_STR,
                     "lastUser": NULLABLE_STR, "lastIp": NULLABLE_STR}),
    "Kpi": obj({"value": INT, "previous": INT}),
    "Overview": obj({
        "window": obj({"hours": INT, "from": TS, "to": TS, "bucketMinutes": INT}),
        "kpis": obj({"events": ref("Kpi"), "failedLogins": ref("Kpi"), "successfulLogins": ref("Kpi"),
                     "honeypotHits": ref("Kpi"), "deniedAccess": ref("Kpi"),
                     "openIncidents": obj({"value": INT, "bySeverity": {"type": "object", "additionalProperties": INT}}),
                     "highRiskUsers": obj({"value": INT})}),
        "timeline": arr(obj({"t": TS, **{s: INT for s in SEVERITIES}})),
        "topSources": arr(obj({"ip": STR, "failures": INT, "accounts": INT})),
        "riskUsers": arr(obj({"username": STR, "fullName": STR, "role": STR, "riskScore": INT})),
        "mitre": arr(obj({"tactic": STR, "count": INT, "techniques": arr(STR)})),
        "techniques": arr(obj({"id": STR, "name": STR, "tactic": NULLABLE_STR, "events": INT, "incidents": INT})),
        "accountActivity": obj({"total": INT, "buckets": arr(TS),
                                "accounts": arr(obj({"username": NULLABLE_STR, "label": STR, "total": INT, "counts": arr(INT)}))}),
        "latestEventId": INT}),
    "DemoAccounts": obj({"demo": BOOL, "accounts": arr(obj({"username": STR, "label": STR, "opens": STR, "password": STR}))}),
}

RESP_ERR = {
    "401": {"description": "Not signed in, or the token is invalid or expired.", "content": {"application/json": {"schema": ref("Error")}}},
    "403": {"description": "Signed in but not allowed (Admin only), or the CSRF header is missing on a cookie-authenticated write.",
            "content": {"application/json": {"schema": ref("Error")}}},
}


def _json(schema, desc="OK", code="200"):
    return {code: {"description": desc, "content": {"application/json": {"schema": schema}}}}


def _body(schema_name, example):
    return {"required": True, "content": {"application/json": {"schema": ref(schema_name), "example": example}}}


def _csv_param(name, desc, enum):
    return {"name": name, "in": "query", "description": desc + " Comma-separated.", "schema": {"type": "string"},
            "example": ",".join(enum[:2])}


def _op(tag, op_id, summary, desc=None, params=None, body=None, responses=None, admin=False, public=False):
    op = {"tags": [tag], "operationId": op_id, "summary": summary, "responses": {}}
    if desc:
        op["description"] = desc
    if params:
        op["parameters"] = params
    if body:
        op["requestBody"] = body
    op["responses"].update(responses or {})
    if public:
        op["security"] = []
    else:
        op["responses"].update({"401": RESP_ERR["401"], **({"403": RESP_ERR["403"]} if admin or body else {})})
    if admin:
        op["x-admin-only"] = True
        op["description"] = ((desc + "\n\n") if desc else "") + "**Admin only.**"
    return op


ID = {"name": "incident_id", "in": "path", "required": True, "schema": INT, "example": 1}

PATHS = {
    "/api/login": {"post": _op("Auth", "login", "Sign in", public=True,
        desc="Returns a JWT and sets two cookies: `oculus_token` (httpOnly, SameSite=Strict) and `oculus_csrf`. "
             "API clients can ignore the cookies and send `Authorization: Bearer <token>` (no CSRF header needed). "
             "Five failures from one address for one account, or 20 from one address in 15 minutes, lock that address out (429).",
        body=_body("LoginRequest", {"username": "imran.shah@oculus.com", "password": "Oculus#Admin26"}),
        responses={**_json(ref("LoginResponse")), "400": {"description": "Missing username or password.", "content": {"application/json": {"schema": ref("Error")}}},
                   "401": {"description": "Wrong credentials. Same message for unknown user and wrong password.", "content": {"application/json": {"schema": ref("Error")}}},
                   "429": {"description": "Locked out. See the Retry-After header (seconds).", "headers": {"Retry-After": {"schema": INT}},
                           "content": {"application/json": {"schema": ref("Error")}}}})},
    "/api/logout": {"post": _op("Auth", "logout", "Sign out", desc="Clears the auth cookies. Records a logout event.",
        responses=_json(obj({"success": {"const": True}})))},
    "/api/me": {"get": _op("Auth", "me", "Current user", responses=_json(ref("User")))},
    "/api/demo-accounts": {"get": _op("Auth", "demoAccounts", "Demo sign-ins", public=True,
        desc="Fictional seeded accounts for one-click demo sign-in. Returns `demo: false` and an empty list unless the server runs in demo mode.",
        responses=_json(ref("DemoAccounts")))},

    "/api/resources": {"get": _op("Workspace", "listResources", "List files",
        desc="Every file, categorised for the caller's role. The role comes from the token, never from the request.",
        responses=_json(arr(ref("Resource"))))},
    "/api/access": {"post": _op("Workspace", "openResource", "Open a file",
        desc="Decides, logs and scores the access. Denied access adds risk points; opening a decoy adds more and raises an incident, "
             "while the caller still sees a normal success.",
        body=_body("AccessRequest", {"resourceName": "Firewall.config"}), responses=_json(ref("AccessResult")))},
    "/api/my/recent": {"get": _op("Workspace", "myRecent", "Recently opened files",
        desc="Distinct files the caller opened (denied attempts excluded), newest first.", responses=_json(arr(ref("RecentFile"))))},

    "/api/overview": {"get": _op("Console", "overview", "Dashboard aggregates", admin=True,
        desc="Everything the Overview page needs in one call: KPIs with the prior-period value, a severity timeline, MITRE techniques, "
             "top accounts, top attacking sources and the highest insider risk.",
        params=[{"name": "hours", "in": "query", "description": "Window. Anything other than 1, 6, 24 or 168 falls back to 24.",
                 "schema": {"type": "integer", "enum": [1, 6, 24, 168], "default": 24}}], responses=_json(ref("Overview")))},
    "/api/events": {"get": _op("Console", "searchEvents", "Search security events", admin=True,
        desc="Newest first. `since_id` returns only newer events, oldest first: that is what the live view polls. `before_id` pages backwards.",
        params=[_csv_param("type", "Event types.", list(EVENT_TYPES)), _csv_param("outcome", "Outcomes.", list(OUTCOMES)),
                _csv_param("severity", "Severities.", list(SEVERITIES)),
                {"name": "user", "in": "query", "description": "Exact username.", "schema": STR},
                {"name": "ip", "in": "query", "description": "Exact IP address (400 if invalid).", "schema": STR},
                {"name": "hours", "in": "query", "description": "Only the last N hours (max 720).", "schema": INT},
                {"name": "q", "in": "query", "description": "Free text over username, file name and IP.", "schema": STR},
                {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500}},
                {"name": "since_id", "in": "query", "schema": INT}, {"name": "before_id", "in": "query", "schema": INT}],
        responses={**_json(ref("EventList")), "400": {"description": "Invalid IP address.", "content": {"application/json": {"schema": ref("Error")}}}})},
    "/api/incidents": {"get": _op("Console", "listIncidents", "List incidents", admin=True,
        params=[_csv_param("status", "Statuses.", list(INCIDENT_STATUSES)), _csv_param("severity", "Severities.", list(SEVERITIES)),
                {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200, "maximum": 500}}],
        responses=_json(arr(ref("Incident"))))},
    "/api/incidents/{incident_id}": {
        "get": _op("Console", "getIncident", "Get an incident", admin=True, params=[ID], responses={
            **_json(ref("Incident")), "404": {"description": "No such incident.", "content": {"application/json": {"schema": ref("Error")}}}}),
        "patch": _op("Console", "updateIncident", "Change status", admin=True, params=[ID],
            desc="Allowed moves: open -> investigating -> resolved, and reopening. Every change is written to the incident's activity trail. "
                 "A closed incident cannot be reopened while another open incident exists for the same subject (409).",
            body=_body("IncidentUpdate", {"status": "investigating", "note": "Reviewing the source address."}),
            responses={**_json(ref("IncidentResult")), "400": {"description": "Unknown status or invalid transition.", "content": {"application/json": {"schema": ref("Error")}}},
                       "404": {"description": "No such incident.", "content": {"application/json": {"schema": ref("Error")}}},
                       "409": {"description": "Another open incident already exists for this subject.", "content": {"application/json": {"schema": ref("Error")}}}})},
    "/api/incidents/{incident_id}/timeline": {"get": _op("Console", "incidentTimeline", "Correlated timeline", admin=True, params=[ID],
        desc="The evidence events that raised the incident, the analyst activity trail, and (as `linked: false`) nearby events from the same subject for context.",
        responses={**_json(ref("Timeline")), "404": {"description": "No such incident.", "content": {"application/json": {"schema": ref("Error")}}}})},
    "/api/incidents/{incident_id}/notes": {"post": _op("Console", "addNote", "Add an analyst note", admin=True, params=[ID],
        body=_body("NoteRequest", {"note": "Confirmed with the user. Password reset requested."}),
        responses={**_json(ref("IncidentResult"), "Created", "201"), "400": {"description": "Empty note.", "content": {"application/json": {"schema": ref("Error")}}},
                   "404": {"description": "No such incident.", "content": {"application/json": {"schema": ref("Error")}}}})},
    "/api/rules": {"get": _op("Console", "listRules", "Detection catalogue", admin=True,
        desc="Every detection rule with its MITRE ATT&CK mapping and how many incidents it has raised.", responses=_json(arr(ref("Rule"))))},
    "/api/honeypots": {"get": _op("Console", "listHoneypots", "Decoy inventory", admin=True,
        desc="Every decoy file, how often it was opened and by whom last.", responses=_json(arr(ref("Honeypot"))))},

    "/api/employees": {
        "get": _op("Admin", "listEmployees", "List employees", admin=True,
            desc="Includes current (decayed) risk score and last sign-in. Password hashes are never returned.", responses=_json(arr(ref("Employee")))),
        "post": _op("Admin", "addEmployee", "Add an employee", admin=True,
            desc="Creates an employee (role is a department). Admin accounts cannot be created through the API.",
            body=_body("NewEmployee", {"fullName": "New Hire", "username": "new.hire@oculus.com", "password": "Passw0rd!2026",
                                       "employeeId": "OC-2000", "role": "HR"}),
            responses={**_json(obj({"success": {"const": True}, "user": ref("Employee")}), "Created", "201"),
                       "400": {"description": "Validation failed (missing field, weak password, markup in a name, unknown role).", "content": {"application/json": {"schema": ref("Error")}}},
                       "409": {"description": "Username or employee id already exists.", "content": {"application/json": {"schema": ref("Error")}}}})},
}


def build_spec():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Oculus API", "version": "1.0.0",
                 "description": "SIEM with honeypot-based insider-threat detection.\n\n"
                                "**Try it:** call `POST /api/login`, copy the `token` from the response, press **Authorize** and paste it. "
                                "Seeded demo accounts are listed in the README (`imran.shah@oculus.com` is an analyst).\n\n"
                                "**Auth:** a JWT, as a Bearer token or an httpOnly cookie. Cookie writes also need an `X-CSRF-Token` header "
                                "equal to the `oculus_csrf` cookie; Bearer clients do not.\n\n"
                                "**Errors:** always `{\"success\": false, \"message\": \"...\"}`.",
                 "license": {"name": "MIT"}},
        "servers": [{"url": "/", "description": "This server"}],
        "tags": [{"name": "Auth"}, {"name": "Workspace", "description": "What employees use."},
                 {"name": "Console", "description": "What security analysts use. Admin only."},
                 {"name": "Admin", "description": "User management. Admin only."}],
        "security": [{"bearerAuth": []}, {"cookieAuth": []}],
        "paths": PATHS,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "Token from POST /api/login."},
                "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "oculus_token",
                               "description": "Set by login. Writes also need the X-CSRF-Token header."}},
            "schemas": SCHEMAS},
    }
