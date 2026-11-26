from dataclasses import dataclass


@dataclass(frozen=True)
class FirewallTarget:
    name: str
    driver: str
    base_url: str
    alias: str
    ca_bundle: str
    api_key_env: str
    api_secret_env: str
    application_managed_expiry: bool
