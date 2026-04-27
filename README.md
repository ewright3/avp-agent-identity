# avp-agent-identity

A reference architecture demonstrating agent identity as a first-class principal using Amazon Verified Permissions (AVP), Bitwarden Secrets Manager (BWS), and the Claude API.

Built as the companion environment for [Developer Network Segmentation Is Not the Same as Server Segmentation](https://ewright3.com/blog/developer-network-segmentation?utm_source=github&utm_medium=readme&utm_campaign=developer-network-segmentation) on [Field Notes](https://ewright3.com).

---

## The Problem

When a security engineer runs an AI tool on their workstation, that tool inherits the engineer's credentials. If the engineer has access to sensitive incident data, so does the agent. Not because anyone decided the agent should have that access. Because nobody decided it shouldn't.

The standard answer is to instruct the agent not to access sensitive data. That is not a security control. An instruction can be overridden by a prompt. A Cedar policy evaluated by Amazon Verified Permissions cannot.

---

## What This Demonstrates

Two principals. One incidents table. Different field-level access. All enforced at the authorization layer, not the application layer.

| Principal | Incident title, severity, status | Affected customers, internal notes, remediation details |
|---|---|---|
| **KB agent** | Read | **Deny (AVP ceiling)** |
| **Security engineer (standard)** | Read | **Deny** |
| **Security engineer (elevated)** | Read | Read (JIT) |

The KB agent and the security engineer run as sibling processes inside the same container, on the same OS. The engineer may elevate to access sensitive incident fields. The agent cannot, because its Cedar identity has no permit for sensitive fields — and a ceiling `forbid` policy means no developer can configure any agent to exceed that limit, regardless of what they put in code or environment variables.

---

## The Core Claim

**Same table. Same OS. Different scope. Enforced at the authorization layer.**

The KB agent queries the same `incidents` table the engineer uses. AVP evaluates every request against Cedar policies before any data is returned. The agent gets public fields. The engineer gets public fields by default, and sensitive fields when elevated. The separation is not a prompt, a system instruction, or a network rule. It is a Cedar policy.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  workspace container — simulates a shared developer workstation      │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  same OS  ·  same filesystem  ·  same network               │    │
│  │                                                               │    │
│  │  ┌───────────────────────┐   ┌───────────────────────────┐  │    │
│  │  │  KB Agent             │   │  Security Engineer Portal  │  │    │
│  │  │  Chainlit  port 8000  │   │  FastAPI   port 8001       │  │    │
│  │  │  Debug API port 8002  │   │                            │  │    │
│  │  │                       │   │                            │  │    │
│  │  │  Principal: kb-agent  │   │  Principal:                │  │    │
│  │  │  BWS token: KB_BWS_   │   │    security-engineer       │  │    │
│  │  │    TOKEN              │   │  BWS token: SECURITY_      │  │    │
│  │  │  (engineer token      │   │    ENGINEER_BWS_TOKEN      │  │    │
│  │  │   stripped at launch) │   │  (full container env)      │  │    │
│  │  └──────────┬────────────┘   └─────────────┬──────────────┘  │    │
│  │             │                               │                  │    │
│  └─────────────┼───────────────────────────────┼──────────────────┘    │
│                │                               │                        │
│                └───────────────┬───────────────┘                        │
│                                │ IsAuthorized() before every access     │
│                                ▼                                        │
│                      ┌──────────────────┐                              │
│                      │  AVP  (AWS)      │ ← Cedar policies             │
│                      │  IsAuthorized    │                              │
│                      └────────┬─────────┘                              │
│                               │ ALLOW / DENY + CloudWatch log          │
│                               ▼                                        │
│                      ┌──────────────────┐                              │
│                      │  incidents       │                              │
│                      │  Postgres        │                              │
│                      │                  │                              │
│                      │  public fields:  │                              │
│                      │  id, title,      │                              │
│                      │  severity,       │                              │
│                      │  status,         │                              │
│                      │  created_at      │                              │
│                      │                  │                              │
│                      │  sensitive:      │                              │
│                      │  affected_       │                              │
│                      │  customers,      │                              │
│                      │  internal_notes, │                              │
│                      │  remediation_    │                              │
│                      │  details,        │                              │
│                      │  postmortem_url  │                              │
│                      └──────────────────┘                              │
└─────────────────────────────────────────────────────────────────────┘
```

### How credential isolation works inside the container

The container environment holds both machine account tokens. The entrypoint script (`workspace/entrypoint.sh`) manages which token each process sees:

```
Container environment:
  KB_BWS_TOKEN=<kb-agent machine account token>
  SECURITY_ENGINEER_BWS_TOKEN=<engineer machine account token>

KB agent process launch:
  env -u SECURITY_ENGINEER_BWS_TOKEN \
      BWS_ACCESS_TOKEN="$KB_BWS_TOKEN" \
      chainlit run kb_agent/app.py ...

Engineer portal process launch:
  BWS_ACCESS_TOKEN="$SECURITY_ENGINEER_BWS_TOKEN" \
      uvicorn engineer.main:app ...
```

The KB agent process cannot see `SECURITY_ENGINEER_BWS_TOKEN`. Both processes share the same OS. The isolation is per-process, not per-container.

### How AVP enforces field-level access

AVP does not enforce column-level access natively. The pattern used here models the two access levels as separate resources:

- `incidents`: public fields (title, severity, status, created_at)
- `incidents_sensitive`: full record including all sensitive fields

The application calls `IsAuthorized` with the appropriate resource before querying the database. Cedar evaluates the policy and returns ALLOW or DENY. The application applies the column filter based on the decision.

```
KB agent request flow:
  IsAuthorized(principal=kb-agent, action=read, resource=incidents) → ALLOW
  SELECT id, title, severity, status, created_at FROM incidents

KB agent attempt on sensitive fields:
  IsAuthorized(principal=kb-agent, action=read, resource=incidents_sensitive) → DENY
  No query runs. Denial logged to CloudWatch.

Engineer (elevated) request flow:
  IsAuthorized(principal=security-engineer, action=read, resource=incidents_sensitive,
               context={elevation_active: true}) → ALLOW
  SELECT * FROM incidents
```

### Cedar policies

```cedar
// KB agent: permitted to read public fields
permit(
  principal == AgentIdentity::Agent::"kb-agent",
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents"
);

// KB agent: explicitly forbidden from sensitive fields
forbid(
  principal == AgentIdentity::Agent::"kb-agent",
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents_sensitive"
);

// Permission ceiling: no agent principal can ever reach sensitive fields.
// A permit policy added for any agent is always overridden by this forbid.
forbid(
  principal is AgentIdentity::Agent,
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents_sensitive"
);

// Security engineer (standard): public fields only
permit(
  principal == AgentIdentity::User::"security-engineer",
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents"
);

// Security engineer (elevated): full record, JIT only
permit(
  principal == AgentIdentity::User::"security-engineer",
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents_sensitive"
)
when { context.elevation_active == true };
```

---

## Prerequisites

Three external accounts are required. This is intentional: the setup demonstrates the credential separation the architecture depends on.

| Service | Purpose | Pricing |
|---|---|---|
| [AWS](https://aws.amazon.com) | Amazon Verified Permissions | $5 / million authorization requests |
| [Anthropic](https://console.anthropic.com) | Claude API | Pay per token |
| [Bitwarden](https://bitwarden.com/products/secrets-manager/) | Secrets Manager | Free tier available |

You will also need:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- [AWS CLI](https://aws.amazon.com/cli/) configured with `verifiedpermissions:*` permissions

---

## Setup

### 1. Provision AVP (Terraform)

```bash
cd terraform
terraform init
terraform apply
```

Terraform creates the AVP policy store, all Cedar policies, an IAM user with least-privilege access, and an access key. Copy these outputs — you will need them in the next step:

```
Outputs:
  policy_store_id       = "AbCdEf1234567890"
  aws_access_key_id     = "AKIAIOSFODNN7EXAMPLE"
  aws_secret_access_key = <sensitive>
```

To retrieve the secret key:

```bash
terraform output -raw aws_secret_access_key
```

### 2. Configure Bitwarden Secrets Manager

In the [Bitwarden Secrets Manager console](https://sm.bitwarden.com):

**Create a project** named `avp-agent-identity`.

**Add these secrets** to the project:

| Key | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |
| `AWS_ACCESS_KEY_ID` | from `terraform output aws_access_key_id` |
| `AWS_SECRET_ACCESS_KEY` | from `terraform output -raw aws_secret_access_key` |
| `DB_INCIDENTS_PASSWORD` | A strong random password you choose |

These are the only place these values live. They are never written to a file on disk.

**Create two machine accounts**, both with read access to the `avp-agent-identity` project:

1. `kb-agent`: the identity the KB agent process uses. Copy the access token.
2. `security-engineer`: the identity the engineer portal process uses. Copy the access token.

These are separate principals with separate credentials. Neither can use the other's token.

### 3. Configure environment variables

```bash
cp .env.example .env
```

Fill in all values:

```env
KB_BWS_TOKEN=                  # kb-agent machine account token
SECURITY_ENGINEER_BWS_TOKEN=   # security-engineer machine account token
BWS_ORGANIZATION_ID=           # UUID from your BWS org URL
AVP_POLICY_STORE_ID=           # from terraform output
AWS_REGION=us-east-1
```

> **Finding your Organization ID:** Open the Bitwarden Secrets Manager or Admin Console. The UUID in the URL is your Organization ID.

> **No secrets in this file.** The DB password, AWS credentials, and Anthropic API key all live in BWS and are injected at startup. Do not commit `.env` to version control.

### 4. Start the stack

Install the BWS CLI if you haven't already. Download the binary for your platform from the [BWS releases page](https://github.com/bitwarden/sdk-sm/releases/tag/bws-v2.0.0) and move it to your PATH:

```bash
mv bws /usr/local/bin/bws
chmod +x /usr/local/bin/bws
```

`bws run` wraps `docker compose up` and injects all BWS secrets as environment variables at startup. The passwords are never written to disk.

```bash
bws run --access-token <your-personal-bws-token> --project-id <avp-agent-identity-project-uuid> -- 'docker compose up --build'
```

Services:

- **KB agent UI:** http://localhost:8000
- **Engineer portal + API docs:** http://localhost:8001/docs
- **KB agent debug:** http://localhost:8002/debug/env-scope

---

## Demo Walkthrough

Run these in order. Each moment isolates one claim.

---

### Moment 1: KB agent reads public incident fields

Open http://localhost:8000 and send:

> "Show me all open incidents."

The agent calls `IsAuthorized` for `read` on `incidents`. Cedar permits it. The agent returns titles, severities, and statuses — no sensitive fields.

Then ask:

> "What are the affected customers for incident 1?"

The agent calls `get_sensitive_details`. The handler calls `IsAuthorized` for `read` on `incidents_sensitive`. AVP returns `DENY`. No query runs. The agent explains that sensitive fields are not accessible to this tool.

---

### Moment 2: Engineer queries incidents without elevation

First, open an interactive shell inside the workspace container. This puts you in the security engineer's environment — the same OS both processes are running on:

```bash
docker exec -it avp-agent-identity-workspace-1 bash
```

Run all remaining curl commands from this shell.

```bash
curl -s http://localhost:8001/incidents | python3 -m json.tool
```

The engineer portal calls `IsAuthorized` for `read` on `incidents` with `elevation_active: false`. Cedar permits it. The response contains the same public fields the KB agent sees: title, severity, status, created_at. No sensitive fields.

Same table. Same data. Same view as the agent — because the standard engineer role has the same public-field permit the KB agent has.

---

### Moment 3: Engineer elevates and gets the full record

```bash
curl -s http://localhost:8001/incidents -H "X-Elevated: true" | python3 -m json.tool
```

The portal calls `IsAuthorized` for `read` on `incidents_sensitive` with `elevation_active: true`. Cedar evaluates the JIT policy and returns `ALLOW`. The full incident record is returned: affected customers, internal notes, remediation details, postmortem URL.

The KB agent is still running at http://localhost:8000. Go back and ask:

> "Now can you show me the affected customers for incident 1?"

The agent still cannot. The engineer's elevation was a separate AVP context evaluation for a separate principal. The agent's Cedar policy did not change.

---

### Moment 4: The permission ceiling

The Terraform config includes a `forbid` policy that applies to all agent principals regardless of any other configuration:

```cedar
forbid(
  principal is AgentIdentity::Agent,
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents_sensitive"
);
```

To verify: add a `permit` policy for the `kb-agent` principal on `incidents_sensitive` in `terraform/main.tf` and run `terraform apply`. Then ask the KB agent for sensitive fields again. The `forbid` overrides the `permit`. Cedar's explicit deny always wins.

This is the control plane. The security team defines the ceiling. Developers cannot exceed it by changing application code, environment variables, or agent configuration.

---

### Moment 5: Credential scope isolation on a shared OS

Both the KB agent and the engineer portal are running inside the same container — the same OS, the same filesystem, the same network. The credential separation is per-process, not per-container.

**Engineer portal** (inherits full container env, including `SECURITY_ENGINEER_BWS_TOKEN`):

```bash
curl -s http://localhost:8001/debug/env-scope | python3 -m json.tool
```

Expected:
```json
{
  "process": "security-engineer-portal",
  "SECURITY_ENGINEER_BWS_TOKEN_visible": true,
  "note": "PASS: engineer token is visible to this process (expected)."
}
```

**KB agent process** (`SECURITY_ENGINEER_BWS_TOKEN` stripped at launch by entrypoint.sh):

```bash
curl -s http://localhost:8002/debug/env-scope | python3 -m json.tool
```

Expected:
```json
{
  "process": "kb-agent",
  "SECURITY_ENGINEER_BWS_TOKEN_visible": false,
  "note": "PASS: engineer token is not visible to the KB agent. Process-level credential isolation is working."
}
```

Same container. Different process environment. The isolation is enforced by `entrypoint.sh` using `env -u SECURITY_ENGINEER_BWS_TOKEN` before launching the agent process.

**The honest residual:** this separation is a code discipline control, not a technical guarantee. A developer who removes the `env -u` line in `entrypoint.sh` collapses the isolation silently. AVP still enforces authorization at the policy layer — the Cedar ceiling still holds — but the credential scoping is gone. This is a code review requirement, not an enforcement mechanism.

---

## Project Structure

```
avp-agent-identity/
├── workspace/
│   ├── Dockerfile            Single container image for both processes
│   ├── entrypoint.sh         Launches both processes with per-process credential scoping
│   ├── bws_secrets.py        BWS SDK loader (shared by both processes)
│   ├── requirements.txt      All Python dependencies
│   ├── kb_agent/
│   │   ├── app.py            Chainlit KB agent — AVP on every data access
│   │   └── debug.py          Debug API — exposes /debug/env-scope on port 8002
│   └── engineer/
│       └── main.py           FastAPI engineer portal — standard and elevated access
├── postgres/
│   └── init/
│       └── incidents.sql     Schema + seed data (5 realistic incidents)
├── terraform/
│   ├── main.tf               AVP policy store, Cedar policies, ceiling forbid, IAM
│   └── variables.tf
├── docker-compose.yml        workspace + db-incidents
├── .env.example
└── .gitignore
```

---

## Teardown

```bash
docker compose down -v
cd terraform && terraform destroy
```

---

## Related Reading

- [Amazon Verified Permissions documentation](https://docs.aws.amazon.com/verifiedpermissions/)
- [Cedar policy language](https://www.cedarpolicy.com)
- [Bitwarden Secrets Manager SDK](https://github.com/bitwarden/sdk)
- [NIST NCCoE: Accelerating the Adoption of Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
