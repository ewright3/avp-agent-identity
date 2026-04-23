"""
avp-agent-identity — Customer Support Chatbot

This agent:
- Opens and reads support cases for the current customer
- Reports service availability status
- Calls AVP IsAuthorized before EVERY data access
- Has no access to investigations or full customer records
  (enforced at the AVP layer, not in this code)

Architecture note:
  The agent's BWS machine account token is in .env.local (project level).
  The developer's personal token is a user-level env var and is NOT visible here.
  This is the credential scoping pattern the architecture demonstrates.
"""

import os
import json
import boto3
import psycopg2
import chainlit as cl
from anthropic import Anthropic
from secrets import load_secrets

# ---------------------------------------------------------------------------
# Secrets: fetched from BWS at startup using the machine account token.
# BWS_ACCESS_TOKEN and BWS_ORGANIZATION_ID come from the environment.
# Everything else (API keys, DB passwords) comes from BWS.
# The developer's personal BWS token is a user-level env var and is never
# visible to this process.
# ---------------------------------------------------------------------------
_secrets = load_secrets()

ANTHROPIC_API_KEY        = _secrets["ANTHROPIC_API_KEY"]
DB_CASES_PASSWORD        = _secrets["DB_CASES_PASSWORD"]
DB_AVAILABILITY_PASSWORD = _secrets["DB_AVAILABILITY_PASSWORD"]

# Infrastructure config — not application secrets, stays in env
AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")

# This agent's principal identifier in Cedar policies
AGENT_PRINCIPAL = "AgentIdentity::Agent::\"chatbot-support\""

anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)


# ---------------------------------------------------------------------------
# AVP authorization helper
# Every data access MUST call this first. If it returns False, stop.
# ---------------------------------------------------------------------------
def is_authorized(action: str, resource: str, context: dict = None) -> tuple[bool, str]:
    """
    Call AVP IsAuthorized. Returns (allowed: bool, decision: str).
    Logs every call so denials are visible in the demo output.
    """
    request = {
        "policyStoreId": AVP_POLICY_STORE_ID,
        "principal":     {"entityType": "AgentIdentity::Agent", "entityId": "chatbot-support"},
        "action":        {"actionType": "AgentIdentity::Action", "actionId": action},
        "resource":      {"entityType": "AgentIdentity::DataStore", "entityId": resource},
    }
    if context:
        request["context"] = {"contextMap": {k: {"boolean": v} if isinstance(v, bool) else {"string": v} for k, v in context.items()}}

    response = avp_client.is_authorized(**request)
    decision = response["decision"]  # "ALLOW" or "DENY"
    return decision == "ALLOW", decision


# ---------------------------------------------------------------------------
# Database helpers — only called after AVP permit
# ---------------------------------------------------------------------------
def get_db(host: str, password: str, dbname: str):
    return psycopg2.connect(host=host, dbname=dbname, user="app", password=password)


def get_cases(customer_id: str) -> list[dict]:
    allowed, decision = is_authorized("read", "cases")
    if not allowed:
        raise PermissionError(f"AVP DENY: read cases (decision: {decision})")
    conn = get_db("db-cases", DB_CASES_PASSWORD, "cases")
    with conn.cursor() as cur:
        cur.execute("SELECT id, subject, status, created_at FROM cases WHERE customer_id = %s", (customer_id,))
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "subject": r[1], "status": r[2], "created_at": str(r[3])} for r in rows]


def create_case(customer_id: str, subject: str, body: str) -> dict:
    allowed, decision = is_authorized("write", "cases")
    if not allowed:
        raise PermissionError(f"AVP DENY: write cases (decision: {decision})")
    conn = get_db("db-cases", DB_CASES_PASSWORD, "cases")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO cases (customer_id, subject, body) VALUES (%s, %s, %s) RETURNING id",
            (customer_id, subject, body)
        )
        case_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return {"id": case_id, "subject": subject, "status": "open"}


def get_availability() -> list[dict]:
    allowed, decision = is_authorized("read", "availability")
    if not allowed:
        raise PermissionError(f"AVP DENY: read availability (decision: {decision})")
    conn = get_db("db-availability", DB_AVAILABILITY_PASSWORD, "availability")
    with conn.cursor() as cur:
        cur.execute("SELECT service, status, message FROM availability_events WHERE resolved_at IS NULL")
        rows = cur.fetchall()
    conn.close()
    return [{"service": r[0], "status": r[1], "message": r[2]} for r in rows]


# ---------------------------------------------------------------------------
# Claude tool definitions
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "get_my_cases",
        "description": "Retrieve the current customer's open support cases.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "create_case",
        "description": "Open a new support case on behalf of the current customer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "subject": {"type": "string", "description": "Brief summary of the issue"},
                "body":    {"type": "string", "description": "Full description of the issue"},
            },
            "required": ["subject", "body"],
        },
    },
    {
        "name": "get_service_availability",
        "description": "Check current service availability and any active incidents.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]


def handle_tool_call(tool_name: str, tool_input: dict, customer_id: str) -> str:
    """Execute a tool call and return the result as a string."""
    try:
        if tool_name == "get_my_cases":
            cases = get_cases(customer_id)
            return json.dumps(cases)
        elif tool_name == "create_case":
            case = create_case(customer_id, tool_input["subject"], tool_input["body"])
            return json.dumps(case)
        elif tool_name == "get_service_availability":
            events = get_availability()
            return json.dumps(events)
        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
    except PermissionError as e:
        # AVP denied the request. Return the denial as a tool result so the
        # model knows it cannot fulfill the request — not because it was
        # instructed to refuse, but because the data is unreachable.
        return json.dumps({"error": str(e), "avp_decision": "DENY"})


# ---------------------------------------------------------------------------
# Chainlit handlers
# ---------------------------------------------------------------------------
@cl.on_chat_start
async def on_chat_start():
    # In a real app, customer_id comes from the authenticated session.
    # For the demo, we use a fixed ID to keep setup simple.
    cl.user_session.set("customer_id", "cust-001")
    cl.user_session.set("messages", [])
    await cl.Message(
        content="Hello! I'm the support chatbot. I can help you view your cases, open a new case, or check service availability. How can I help?"
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    customer_id = cl.user_session.get("customer_id")
    messages    = cl.user_session.get("messages")

    messages.append({"role": "user", "content": message.content})

    # Agentic loop: keep calling Claude until no more tool calls
    while True:
        response = anthropic_client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            system=(
                "You are a customer support agent. You can view the customer's support cases, "
                "open new cases, and check service availability. "
                "You do not have access to security investigations or internal records. "
                "If asked about ongoing security incidents or investigation details, "
                "tell the customer you can only share service availability status."
            ),
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "tool_use":
            # Process all tool calls in this response
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = handle_tool_call(block.name, block.input, customer_id)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        else:
            # Final response
            final_text = next(
                (block.text for block in response.content if hasattr(block, "text")), ""
            )
            messages.append({"role": "assistant", "content": final_text})
            cl.user_session.set("messages", messages)
            await cl.Message(content=final_text).send()
            break
