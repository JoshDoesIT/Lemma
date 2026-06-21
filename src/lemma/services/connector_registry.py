"""First-party connector registry (Refs #34, Connector Registry).

A queryable catalog of the connectors Lemma ships, so operators can discover
what's available (and its required config/secret) without instantiating each —
the foundation a community registry extends. Kept as static descriptors
because instantiating a connector needs live credentials; a drift-guard test
asserts this registry stays in sync with the `_first_party_connector` factory.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ConnectorDescriptor:
    """Catalog metadata for one connector."""

    name: str
    producer: str
    description: str
    config_keys: list[str] = field(default_factory=list)
    required_secret: str = ""  # env var holding the credential, if any
    capabilities: list[str] = field(default_factory=list)


FIRST_PARTY_REGISTRY: list[ConnectorDescriptor] = [
    ConnectorDescriptor(
        name="github",
        producer="GitHub",
        description="Repository branch-protection and security posture.",
        config_keys=["repo"],
        required_secret="LEMMA_GITHUB_TOKEN",
        capabilities=["branch-protection", "security-posture"],
    ),
    ConnectorDescriptor(
        name="okta",
        producer="Okta",
        description="MFA enrollment policy and SSO application inventory.",
        config_keys=["domain"],
        required_secret="LEMMA_OKTA_TOKEN",
        capabilities=["mfa-policy", "sso-inventory"],
    ),
    ConnectorDescriptor(
        name="aws",
        producer="AWS",
        description="Account-level CIS-aligned posture (root MFA, password policy, CloudTrail).",
        config_keys=["region"],
        required_secret="",  # AWS default credential chain
        capabilities=["cis-foundations"],
    ),
    ConnectorDescriptor(
        name="jira",
        producer="Jira",
        description="Change-management posture (SOC 2 CC8.1) from a Jira Cloud site.",
        config_keys=["base_url", "email", "jql"],
        required_secret="LEMMA_JIRA_TOKEN",
        capabilities=["change-management"],
    ),
    ConnectorDescriptor(
        name="servicenow",
        producer="ServiceNow",
        description="Change-request posture from the ServiceNow change_request table.",
        config_keys=["instance", "username", "query"],
        required_secret="LEMMA_SERVICENOW_PASSWORD",
        capabilities=["change-management"],
    ),
    ConnectorDescriptor(
        name="azure-devops",
        producer="AzureDevOps",
        description="Change-management posture from Azure DevOps Boards work items.",
        config_keys=["organization", "project", "wiql"],
        required_secret="LEMMA_AZURE_DEVOPS_TOKEN",
        capabilities=["change-management"],
    ),
    ConnectorDescriptor(
        name="azure",
        producer="Azure",
        description="Tenant + subscription posture (Entra ID MFA, Activity Log, Azure Policy).",
        config_keys=["tenant_id", "client_id", "subscription_id"],
        required_secret="LEMMA_AZURE_CLIENT_SECRET",
        capabilities=["entra-mfa", "activity-log", "azure-policy"],
    ),
]


def registry_names() -> list[str]:
    """Connector names present in the registry, sorted."""
    return sorted(d.name for d in FIRST_PARTY_REGISTRY)


def get_descriptor(name: str) -> ConnectorDescriptor | None:
    """Look up a connector descriptor by name, or ``None``."""
    return next((d for d in FIRST_PARTY_REGISTRY if d.name == name), None)
