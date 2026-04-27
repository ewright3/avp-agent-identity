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

### Moment 1: KB agent lists active incidents — no dates

Open http://localhost:8000 and send:

> "Show me the active incidents."

The agent calls `IsAuthorized` for `read` on `incidents_basic`. Cedar permits it. Three incidents are returned: title, severity, and status only. No dates. Incident 3 (Anomalous API access — resolved) is not in the list.

Ask:

> "What happened to incident 3?"

The agent looks it up by ID and explains it was resolved, so it was excluded from the active list.

Ask:

> "When did these incidents start?"

The agent does not have dates. It explains that `created_at` is not in its current authorization scope.

---

### Moment 2: Engineer opens a shell in the shared environment

Open a terminal on the host and exec into the workspace container. This puts you in the same OS where both processes are running:

```bash
docker exec -it avp-agent-identity-workspace-1 bash
```

Verify both processes are running in this environment:

```bash
ps aux | grep -E 'chainlit|uvicorn' | grep -v grep
```

Verify the ports they are listening on:

```bash
ss -tlnp | grep -E '8000|8001|8002'
```

Expected: Chainlit on 8000, uvicorn engineer portal on 8001, uvicorn KB debug on 8002. Same OS. Same process table. Same network namespace.

Run all remaining curl commands from this shell.

---

### Moment 3: Engineer queries incidents — sees dates, no sensitive fields

```bash
curl -s http://localhost:8001/incidents | python3 -m json.tool
```

The engineer portal calls `IsAuthorized` for `read` on `incidents_public`. Cedar permits it. The response includes `created_at` along with title, severity, and status. No sensitive fields.

The engineer can see dates. The KB agent cannot — yet.

---

### Moment 4: Engineer grants the KB agent date access via AWS CLI

The engineer recognizes the KB agent needs `created_at`. They use the AWS CLI to add a permit policy directly in AVP — no Terraform, no application code change.

From your **host terminal** (where your AWS credentials are configured):

```bash
aws verifiedpermissions create-policy \
  --policy-store-id "$AVP_POLICY_STORE_ID" \
  --region us-east-1 \
  --definition '{
    "static": {
      "description": "Engineer grant: kb-agent can read incidents with dates",
      "statement": "permit(principal == AgentIdentity::Agent::\"kb-agent\", action == AgentIdentity::Action::\"read\", resource == AgentIdentity::DataStore::\"incidents_public\");"
    }
  }'
```

AVP returns a policy ID. The policy is now active.

Go back to http://localhost:8000 and ask:

> "Show me the active incidents again."

The agent now returns dates. The Cedar policy was updated at runtime. No restart, no code change, no Terraform apply.

---

### Moment 5: Engineer tries to grant sensitive field access — ceiling blocks it

The engineer notices affected customers are still missing. They try the same approach: add a permit for `incidents_sensitive`.

From your **host terminal**:

```bash
aws verifiedpermissions create-policy \
  --policy-store-id "$AVP_POLICY_STORE_ID" \
  --region us-east-1 \
  --definition '{
    "static": {
      "description": "Engineer attempt: grant kb-agent sensitive field access",
      "statement": "permit(principal == AgentIdentity::Agent::\"kb-agent\", action == AgentIdentity::Action::\"read\", resource == AgentIdentity::DataStore::\"incidents_sensitive\");"
    }
  }'
```

AVP returns a policy ID. The policy was created successfully.

Go back to http://localhost:8000 and ask:

> "Now show me the affected customers for incident 1."

The agent still cannot. The policy exists in the store — you can verify it in the AWS console — but the ceiling `forbid` overrides any `permit` at evaluation time. Cedar's explicit deny always wins.

```cedar
// This forbid is defined in Terraform and owned by the security team.
// It cannot be overridden by any permit policy, regardless of who adds it.
forbid(
  principal is AgentIdentity::Agent,
  action == AgentIdentity::Action::"read",
  resource == AgentIdentity::DataStore::"incidents_sensitive"
);
```

The engineer had the AWS permissions to create the policy. The policy exists. The agent still cannot use it. The ceiling is the control the security team defines. Developers and engineers cannot exceed it.

---

### Moment 6: Engineer queries sensitive data directly, then asks the agent one final time

From the container shell:

```bash
curl -s http://localhost:8001/incidents/1 -H "X-Elevated: true" | python3 -m json.tool
```

The engineer portal calls `IsAuthorized` for `read` on `incidents_sensitive` with `elevation_active: true`. Cedar permits it. The full record is returned including affected customers, internal notes, remediation details, and postmortem URL.

Now ask the KB agent the same question one final time at http://localhost:8000:

> "What are the affected customers for incident 1?"

The agent is denied. Same container. Same OS. Same incident. Different principal. Different scope. The KB agent's Cedar identity has no path to `incidents_sensitive`. The ceiling enforces it regardless of what policies exist for the engineer or what the engineer can see directly.

---

### Moment 7: Credential scope isolation on a shared OS

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
