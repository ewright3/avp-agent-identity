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
    value = jsonencode({
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
          }
        },
        "actions": {
          "read":  { "appliesTo": { "principalTypes": ["Agent", "User"], "resourceTypes": ["DataStore"] } },
          "write": { "appliesTo": { "principalTypes": ["Agent", "User"], "resourceTypes": ["DataStore"] } }
        }
      }
    })
  }
}

# --- Chatbot agent policies ---

resource "aws_verifiedpermissions_policy" "chatbot_cases_readwrite" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: read and write support cases"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::Agent::"chatbot-support",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"cases"
        );
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "chatbot_availability_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: read availability events"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::Agent::"chatbot-support",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"availability"
        );
      CEDAR
    }
  }
}

# --- Explicit deny: chatbot cannot reach investigations or customers ---

resource "aws_verifiedpermissions_policy" "chatbot_investigations_deny" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: explicitly forbidden from investigations"
      statement   = <<-CEDAR
        forbid(
          principal == AgentIdentity::Agent::"chatbot-support",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"investigations"
        );
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "chatbot_customers_deny" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Chatbot agent: explicitly forbidden from customer records"
      statement   = <<-CEDAR
        forbid(
          principal == AgentIdentity::Agent::"chatbot-support",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"customers"
        );
      CEDAR
    }
  }
}

# --- Permission ceiling: no agent principal can ever access investigations ---

resource "aws_verifiedpermissions_policy" "agent_ceiling_investigations" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "Ceiling policy: no agent identity may access investigations regardless of configuration"
      statement   = <<-CEDAR
        forbid(
          principal in AgentIdentity::Agent::"*",
          action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
          resource == AgentIdentity::DataStore::"investigations"
        );
      CEDAR
    }
  }
}

# --- SecOps policies ---

resource "aws_verifiedpermissions_policy" "secops_cases_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "SecOps users: read support cases"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"secops",
          action == AgentIdentity::Action::"read",
          resource in [
            AgentIdentity::DataStore::"cases",
            AgentIdentity::DataStore::"availability"
          ]
        );
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "secops_investigations_jit" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    static {
      description = "SecOps users: time-bound JIT access to investigations and customer records"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"secops",
          action == AgentIdentity::Action::"read",
          resource in [
            AgentIdentity::DataStore::"investigations",
            AgentIdentity::DataStore::"customers"
          ]
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
