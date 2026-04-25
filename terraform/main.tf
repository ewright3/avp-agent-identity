terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# AVP Policy Store
resource "aws_verifiedpermissions_policy_store" "main" {
  description = "avp-agent-identity demo policy store"

  validation_settings {
    mode = "STRICT"
  }
}

# Cedar schema
resource "aws_verifiedpermissions_schema" "main" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    value = <<-JSON
      {
        "AgentIdentity": {
          "entityTypes": {
            "Agent": {
              "shape": {
                "type": "Record",
                "attributes": {}
              }
            },
            "User": {
              "shape": {
                "type": "Record",
                "attributes": {
                  "role": { "type": "String", "required": true }
                }
              }
            },
            "DataStore": {
              "shape": {
                "type": "Record",
                "attributes": {}
              }
            }
          },
          "actions": {
            "read":  { "appliesTo": { "principalTypes": ["Agent", "User"], "resourceTypes": ["DataStore"] } },
            "write": { "appliesTo": { "principalTypes": ["Agent", "User"], "resourceTypes": ["DataStore"] } }
          }
        }
      }
    JSON
  }
}

# ---------------------------------------------------------------------------
# Chatbot agent policies
#
# The agent can read orders only when a valid customer session is present.
# context.session_customer_id is passed by the app server — not the client.
# The app then filters the SQL query to WHERE customer_id = session_customer_id.
# The Cedar policy validates the agent is operating within a customer session.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "chatbot_orders_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: read orders within an authenticated customer session"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::Agent::"chatbot-support",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"orders"
        )
        when { context has session_customer_id };
      CEDAR
    }
  }
}

# Explicit deny: chatbot cannot access payments under any circumstance
resource "aws_verifiedpermissions_policy" "chatbot_payments_deny" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: explicitly forbidden from payment records"
      statement   = <<-CEDAR
        forbid(
          principal == AgentIdentity::Agent::"chatbot-support",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"payments"
        );
      CEDAR
    }
  }
}

# Explicit deny: chatbot cannot access system logs
resource "aws_verifiedpermissions_policy" "chatbot_logs_deny" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: explicitly forbidden from system logs"
      statement   = <<-CEDAR
        forbid(
          principal == AgentIdentity::Agent::"chatbot-support",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"system_logs"
        );
      CEDAR
    }
  }
}

# ---------------------------------------------------------------------------
# Permission ceiling
#
# No agent principal — regardless of how a developer configures it —
# can ever access payment records. A permit policy for an agent on payments
# will always be overridden by this forbid.
#
# This is the control plane claim: SecOps defines the ceiling,
# developers cannot exceed it.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "agent_ceiling_payments" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Ceiling policy: no agent identity may access payment records regardless of configuration"
      statement   = <<-CEDAR
        forbid(
          principal is AgentIdentity::Agent,
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"payments"
        );
      CEDAR
    }
  }
}

# ---------------------------------------------------------------------------
# Developer (standard) policies
# Read access to orders and system logs. No access to payments.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "developer_orders_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Developer (standard): read all orders"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"developer",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"orders"
        );
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "developer_logs_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Developer (standard): read system logs"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"developer",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"system_logs"
        );
      CEDAR
    }
  }
}

# ---------------------------------------------------------------------------
# Developer (elevated) policies
# JIT access to payments and write access to orders.
# Elevation is a context attribute passed by the app server.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "developer_orders_write_elevated" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Developer (elevated): read and write all orders"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"developer",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"orders"
        )
        when { context.elevation_active == true };
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "developer_payments_elevated" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Developer (elevated): read payment records — JIT only"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"developer",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"payments"
        )
        when { context.elevation_active == true };
      CEDAR
    }
  }
}

output "policy_store_id" {
  description = "Copy this value into AVP_POLICY_STORE_ID in your .env file"
  value       = aws_verifiedpermissions_policy_store.main.id
}
