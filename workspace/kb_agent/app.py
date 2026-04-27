"""
avp-agent-identity — Incident Knowledge Base Agent

This agent helps the security team find and summarize active incidents.
What it can see depends on which Cedar policies are active for kb-agent:

  incidents_basic     — title, severity, status only (starting state)
  incidents_public    — adds created_at (granted by engineer via AWS CLI)
  incidents_sensitive — adds sensitive fields (ceiling forbid blocks this always)

The agent checks authorization level at runtime and returns the most
permissive view it is allowed to see.

The key demo moments:
  1. Agent lists active incidents — incident 3 (resolved) is not shown.
  2. Engineer asks about incident 3 — agent explains it is resolved.
  3. Engineer notices dates are missing — agent confirms it lacks that permission.
  4. Engineer grants incidents_public via AWS CLI — dates now appear.
  5. Engineer tries to grant incidents_sensitive via AWS CLI — policy is created
     but AVP still returns DENY because the ceiling forbid overrides any permit.
  6. Engineer queries directly with elevation — sees sensitive fields.
  7. Engineer asks agent one final time — agent still cannot see sensitive fields.

Credential scoping:
  This process is launched by entrypoint.sh with SECURITY_ENGINEER_BWS_TOKEN
  stripped from its environment. It cannot see the engineer's credential even
  though both processes share the same container OS.
"""

import os
import json
import sys
import boto3
import psycopg2
import chainlit as cl
from anthropic import Anthropic

sys.path.insert(0, "/app")
from bws_secrets import load_secrets

# ---------------------------------------------------------------------------
# Secrets and config
# ---------------------------------------------------------------------------
_secrets = load_secrets()

ANTHROPIC_API_KEY     = _secrets["ANTHROPIC_API_KEY"]
DB_INCIDENTS_PASSWORD = _secrets["DB_INCIDENTS_PASSWORD"]

AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")
AGENT_PRINCIPAL_ID  = "kb-agent"

anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)

# Column sets per authorization tier
COLUMNS_BASIC  = ["id", "title", "severity", "status"]
COLUMNS_PUBLIC = ["id", "title", "severity", "status", "created_at"]
COLUMNS_ALL    = ["id", "title", "severity", "status", "created_at",
                  "affected_customers", "internal_notes", "remediation_details", "postmortem_url"]


# ---------------------------------------------------------------------------
# AVP authorization helpers
# ---------------------------------------------------------------------------
def is_authorized(action: str, resource: str) -> tuple[bool, str]:
    response = avp_client.is_authorized(
        policyStoreId=AVP_POLICY_STORE_ID,
        principal={"entityType": "AgentIdentity::Agent", "entityId": AGENT_PRINCIPAL_ID},
        action={"actionType": "AgentIdentity::Action", "actionId": action},
        resource={"entityType": "AgentIdentity::DataStore", "entityId": resource},
        context={"contextMap": {"elevation_active": {"boolean": False}}},
    )
    decision = response["decision"]
    return decision == "ALLOW", decision


def get_auth_level() -> str:
    """
    Check what tier of incident data this agent is currently authorized to read.
    Checks from most to least permissive. Returns the highest permitted tier.
    The ceiling forbid means incidents_sensitive will always return DENY for agents.
    """
    for resource in ["incidents_sensitive", "incidents_public", "incidents_basic"]:
        allowed, _ = is_authorized("read", resource)
        if allowed:
            return resource
    raise PermissionError(
        "AVP DENY: no permit found for any incident resource. "
        "The kb-agent principal has no active Cedar policy granting read access."
    )


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    return psycopg2.connect(
        host="db-incidents",
        dbname="incidents",
        user="app",
        password=DB_INCIDENTS_PASSWORD,
    )


def row_to_dict(row: tuple, columns: list[str]) -> dict:
    return {col: (str(val) if val is not None else None) for col, val in zip(columns, row)}


def list_active_incidents() -> dict:
    """
    List incidents that are not resolved. Resolved incidents are excluded
    because they are no longer active. The caller can look up any incident
    by ID if they want to check on a resolved one.
    """
    auth_level = get_auth_level()

    if auth_level == "incidents_sensitive":
        select = "id, title, severity, status, created_at, affected_customers, internal_notes, remediation_details, postmortem_url"
        columns = COLUMNS_ALL
    elif auth_level == "incidents_public":
        select = "id, title, severity, status, created_at"
        columns = COLUMNS_PUBLIC
    else:
        select = "id, title, severity, status"
        columns = COLUMNS_BASIC

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT {select} FROM incidents WHERE status != 'resolved' ORDER BY created_at DESC"
        )
        rows = cur.fetchall()
    conn.close()
    return {"auth_level": auth_level, "incidents": [row_to_dict(r, columns) for r in rows]}


def get_incident_by_id(incident_id: int) -> dict:
    """
    Get any incident by ID regardless of status. Used to explain why
    an incident is not in the active list.
    """
    auth_level = get_auth_level()

    if auth_level == "incidents_sensitive":
        select = "id, title, severity, status, created_at, affected_customers, internal_notes, remediation_details, postmortem_url"
        columns = COLUMNS_ALL
    elif auth_level == "incidents_public":
        select = "id, title, severity, status, created_at"
        columns = COLUMNS_PUBLIC
    else:
        select = "id, title, severity, status"
        columns = COLUMNS_BASIC

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(f"SELECT {select} FROM incidents WHERE id = %s", (incident_id,))
        row = cur.fetchone()
    conn.close()
    if not row:
        return {"error": f"Incident {incident_id} not found."}
    return {"auth_level": auth_level, "incident": row_to_dict(row, columns)}


def attempt_sensitive_field(incident_id: int) -> str:
    """
    Called when the agent is asked for sensitive fields directly.
    AVP will DENY because the ceiling forbid blocks all agent principals
    from incidents_sensitive regardless of any permit policies.
    """
    allowed, decision = is_authorized("read", "incidents_sensitive")
    if not allowed:
        raise PermissionError(
            f"AVP DENY: read incidents_sensitive (decision: {decision}). "
            f"The ceiling forbid policy blocks all agent principals from sensitive fields. "
            f"A permit policy exists for kb-agent but the ceiling overrides it. "
            f"This denial is logged in CloudWatch."
        )
    return "unreachable"


# ---------------------------------------------------------------------------
# Claude tool definitions
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "list_active_incidents",
        "description": (
            "List all active (non-resolved) incidents. "
            "Returns the fields this agent is currently authorized to see. "
            "Resolved incidents are excluded — use get_incident_by_id to look those up."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_incident_by_id",
        "description": (
            "Get details for any incident by ID, including resolved ones. "
            "Returns the fields this agent is currently authorized to see."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "integer", "description": "The incident ID"},
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "get_sensitive_fields",
        "description": (
            "Attempt to retrieve sensitive incident fields: affected customers, internal notes, "
            "remediation details, postmortem URL. "
            "This will always return an AVP DENY — the ceiling forbid blocks all agent principals "
            "from sensitive fields regardless of any permit policies that exist."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "integer", "description": "The incident ID"},
            },
            "required": ["incident_id"],
        },
    },
]


def handle_tool_call(tool_name: str, tool_input: dict) -> str:
    try:
        if tool_name == "list_active_incidents":
            result = list_active_incidents()
            return json.dumps(result)
        elif tool_name == "get_incident_by_id":
            result = get_incident_by_id(tool_input["incident_id"])
            return json.dumps(result)
        elif tool_name == "get_sensitive_fields":
            attempt_sensitive_field(tool_input["incident_id"])
            return json.dumps({"error": "unreachable"})
        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
    except PermissionError as e:
        return json.dumps({"error": str(e), "avp_decision": "DENY"})


# ---------------------------------------------------------------------------
# Chainlit handlers
# ---------------------------------------------------------------------------
@cl.on_chat_start
async def on_chat_start():
    cl.user_session.set("messages", [])
    await cl.Message(
        content=(
            "Security Incident KB. I can list active incidents, look up any incident by ID, "
            "and summarize what I can see. Ask me what you need."
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    messages = cl.user_session.get("messages")
    messages.append({"role": "user", "content": message.content})

    while True:
        response = anthropic_client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            system=(
                "You are a security incident knowledge base assistant. "
                "You list active (non-resolved) incidents by default. Resolved incidents are excluded "
                "from the active list but you can look them up by ID if asked. "
                "When an incident is missing from the active list, explain clearly that it was excluded "
                "because its status is resolved or similar — not active. "
                "The fields you can see depend on your current Cedar authorization level, which may change "
                "at runtime as policies are updated. If dates are not in your response, you do not have "
                "permission to see them yet. Say so directly. "
                "You have a get_sensitive_fields tool but it will always return an AVP DENY because "
                "the ceiling forbid policy blocks all agent principals from sensitive fields regardless "
                "of any other policies that exist. When denied, explain this clearly: a permit policy "
                "may exist but the ceiling overrides it. Do not suggest that different instructions "
                "would change this."
            ),
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = handle_tool_call(block.name, block.input)
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     result,
                    })
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user",      "content": tool_results})
        else:
            final_text = next(
                (block.text for block in response.content if hasattr(block, "text")), ""
            )
            messages.append({"role": "assistant", "content": final_text})
            cl.user_session.set("messages", messages)
            await cl.Message(content=final_text).send()
            break
