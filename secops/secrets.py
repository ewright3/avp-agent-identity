"""
BWS secrets loader.

Authenticates with Bitwarden Secrets Manager using the machine account
token and returns all accessible secrets as a {key: value} dict.
"""

import os
from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict


def load_secrets() -> dict[str, str]:
    """
    Fetch all secrets accessible to this machine account from BWS.
    Returns a {key: value} dict.
    Raises on auth failure or API error — fail fast at startup.
    """
    client = BitwardenClient(
        client_settings_from_dict({
            "apiUrl":      os.environ.get("BWS_API_URL", "https://api.bitwarden.com"),
            "identityUrl": os.environ.get("BWS_IDENTITY_URL", "https://identity.bitwarden.com"),
            "deviceType":  DeviceType.SDK,
            "userAgent":   "avp-agent-identity-secops/1.0",
        })
    )

    client.auth().login_access_token(
        access_token=os.environ["BWS_ACCESS_TOKEN"],
        state_file=os.environ.get("BWS_STATE_FILE"),
    )

    org_id = os.environ["BWS_ORGANIZATION_ID"]

    list_response = client.secrets().list(org_id)
    secret_ids = [item.id for item in list_response.data.data]

    if not secret_ids:
        return {}

    secrets_response = client.secrets().get_by_ids(secret_ids)
    return {s.key: s.value for s in secrets_response.data.data}
