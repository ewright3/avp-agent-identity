"""
avp-agent-identity — SecOps Internal API

This service:
- Allows SecOps/Legal users to query all data stores
- Requires JIT elevation context to access investigations and customers
- Calls AVP IsAuthorized before EVERY data access
- Demonstrates that human JIT elevation does NOT affect the chatbot agent's scope
"""

import os
import json
import boto3
import psycopg2
from fastapi import FastAPI, HTTPException, Header
from secrets import load_secrets

_secrets = load_secrets()

DB_CASES_PASSWORD          = _secrets["DB_CASES_PASSWORD"]
DB_AVAILABILITY_PASSWORD   = _secrets["DB_AVAILABILITY_PASSWORD"]
DB_INVESTIGATIONS_PASSWORD = _secrets["DB_INVESTIGATIONS_PASSWORD"]
DB_CUSTOMERS_PASSWORD      = _secrets["DB_CUSTOMERS_PASSWORD"]

# Infrastructure config — stays in env
AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")

avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)
app = FastAPI(title="SecOps Internal API")


# ---------------------------------------------------------------------------
# AVP authorization helper — same pattern as chatbot, different principal
# ---------------------------------------------------------------------------
def is_authorized(principal_id: str, action: str, resource: str, context: dict = None) -> tuple[bool, str]:
    request = {
        "policyStoreId": AVP_POLICY_STORE_ID,
        "principal":     {"entityType": "AgentIdentity::User", "entityId": principal_id},
        "action":        {"actionType": "AgentIdentity::Action", "actionId": action},
        "resource":      {"entityType": "AgentIdentity::DataStore", "entityId": resource},
    }
    if context:
        request["context"] = {
            "contextMap": {
                k: {"boolean": v} if isinstance(v, bool) else {"string": str(v)}
                for k, v in context.items()
            }
        }
    response = avp_client.is_authorized(**request)
    decision = response["decision"]
    return decision == "ALLOW", decision


def get_db(host: str, password: str, dbname: str):
    return psycopg2.connect(host=host, dbname=dbname, user="app", password=password)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/cases")
def list_cases(x_user: str = Header(default="secops"), x_elevated: bool = Header(default=False)):
    allowed, decision = is_authorized(x_user, "read", "cases")
    if not allowed:
        raise HTTPException(status_code=403, detail=f"AVP DENY: {decision}")
    conn = get_db("db-cases", DB_CASES_PASSWORD, "cases")
    with conn.cursor() as cur:
        cur.execute("SELECT id, customer_id, subject, status, created_at FROM cases")
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "customer_id": r[1], "subject": r[2], "status": r[3], "created_at": str(r[4])} for r in rows]


@app.get("/availability")
def get_availability(x_user: str = Header(default="secops"), x_elevated: bool = Header(default=False)):
    allowed, decision = is_authorized(x_user, "read", "availability")
    if not allowed:
        raise HTTPException(status_code=403, detail=f"AVP DENY: {decision}")
    conn = get_db("db-availability", DB_AVAILABILITY_PASSWORD, "availability")
    with conn.cursor() as cur:
        cur.execute("SELECT service, status, message, started_at FROM availability_events")
        rows = cur.fetchall()
    conn.close()
    return [{"service": r[0], "status": r[1], "message": r[2], "started_at": str(r[3])} for r in rows]


@app.get("/investigations")
def list_investigations(x_user: str = Header(default="secops"), x_elevated: bool = Header(default=False)):
    """
    Requires JIT elevation. Pass X-Elevated: true header to simulate an active elevation session.
    AVP evaluates the elevation_active context attribute against the Cedar policy.
    Without elevation, the Cedar policy denies this request even for SecOps users.
    """
    allowed, decision = is_authorized(x_user, "read", "investigations", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"AVP DENY: {decision}. JIT elevation required. Pass X-Elevated: true to simulate an active elevation session."
        )
    conn = get_db("db-investigations", DB_INVESTIGATIONS_PASSWORD, "investigations")
    with conn.cursor() as cur:
        cur.execute("SELECT id, case_ref, title, classification, summary, status, assigned_to FROM investigations")
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "case_ref": r[1], "title": r[2], "classification": r[3], "summary": r[4], "status": r[5], "assigned_to": r[6]} for r in rows]


@app.get("/customers")
def list_customers(x_user: str = Header(default="secops"), x_elevated: bool = Header(default=False)):
    """Requires JIT elevation. Same pattern as /investigations."""
    allowed, decision = is_authorized(x_user, "read", "customers", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"AVP DENY: {decision}. JIT elevation required. Pass X-Elevated: true to simulate an active elevation session."
        )
    conn = get_db("db-customers", DB_CUSTOMERS_PASSWORD, "customers")
    with conn.cursor() as cur:
        cur.execute("SELECT id, name, email, phone, account_status FROM customers")
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "email": r[2], "phone": r[3], "account_status": r[4]} for r in rows]


@app.get("/health")
def health():
    return {"status": "ok"}
