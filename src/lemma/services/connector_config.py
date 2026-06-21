"""Connector configuration loader (Refs #116).

A `lemma_connector_config.yaml` file lives next to a connector project
and captures connector configuration distinctly from code. Operators
can reconfigure a connector without editing Python; secrets stay in
env vars (referenced via ``${ENV_VAR}`` interpolation) instead of
being checked into git.

Schema:

.. code-block:: yaml

    producer: Lemma          # optional; defaults to project producer
    enabled: true            # optional; default true
    schedule: '0 */6 * * *'  # optional; cron-like, scheduler-side
    connector: github        # required; first-party connector name
    config:                  # required; passed to the connector factory
      repo: octocat/Hello-World
      token: ${GITHUB_TOKEN}
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from lemma.services.secret_backends import SecretBackend

_ENV_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
# ``${secret:NAME}`` pulls from the selected secret backend (#117, #227) —
# the local encrypted store by default, or Vault / AWS Secrets Manager / OS
# keyring — rather than the environment. Names are case-insensitive in the
# regex but resolved as written; resolved before the ${ENV_VAR} pass so the
# two never clash.
_SECRET_REF_RE = re.compile(r"\$\{secret:([A-Za-z_][A-Za-z0-9_]*)\}")


class ConnectorConfig(BaseModel):
    """Validated shape of a ``lemma_connector_config.yaml`` file."""

    model_config = ConfigDict(extra="forbid")

    connector: str = Field(..., min_length=1, description="First-party connector name")
    config: dict[str, Any] = Field(default_factory=dict, description="Connector-specific config")
    producer: str = Field(default="", description="Producer name (defaults to project producer)")
    enabled: bool = Field(default=True, description="Whether this connector should run")
    schedule: str = Field(default="", description="Cron-like schedule (interpreted by scheduler)")


def load_connector_config(
    path: Path, *, secret_store: SecretBackend | None = None
) -> ConnectorConfig:
    """Load, validate, and interpolate a connector config file.

    Resolves ``${secret:NAME}`` references against ``secret_store`` (the
    encrypted store from #117) and ``${ENV_VAR}`` references against the
    environment.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: On malformed YAML, schema-validation failure, a
            ``${VAR}`` reference whose env var is not set, or a
            ``${secret:NAME}`` reference with no store / missing secret.
    """
    path = Path(path)
    if not path.is_file():
        msg = f"Connector config not found: {path}"
        raise FileNotFoundError(msg)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in {path}: {exc}"
        raise ValueError(msg) from exc
    if raw is None:
        msg = f"Connector config is empty: {path}"
        raise ValueError(msg)
    if not isinstance(raw, dict):
        msg = f"Connector config root must be a mapping, got {type(raw).__name__}"
        raise ValueError(msg)

    interpolated = _interpolate(raw, source=str(path), secret_store=secret_store)
    try:
        return ConnectorConfig(**interpolated)
    except Exception as exc:
        msg = f"Invalid connector config in {path}: {exc}"
        raise ValueError(msg) from exc


def _interpolate(value: Any, *, source: str, secret_store: SecretBackend | None) -> Any:
    """Walk a parsed YAML structure and replace ``${...}`` refs in strings.

    Strict: unset env vars / missing secrets raise ``ValueError`` rather than
    substituting empty strings — silently producing an empty token field is
    the exact footgun an operator would never catch.
    """
    if isinstance(value, str):
        return _interpolate_string(value, source=source, secret_store=secret_store)
    if isinstance(value, dict):
        return {
            k: _interpolate(v, source=source, secret_store=secret_store) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_interpolate(v, source=source, secret_store=secret_store) for v in value]
    return value


def _interpolate_string(value: str, *, source: str, secret_store: SecretBackend | None) -> str:
    def secret_repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if secret_store is None:
            msg = (
                f"Secret '{name}' referenced in {source} but no secret store is "
                "available. Set LEMMA_SECRET_PASSPHRASE and add it via "
                "`lemma connector set-secret`."
            )
            raise ValueError(msg)
        secret_value = secret_store.get(name)
        if secret_value is None:
            msg = (
                f"Secret '{name}' referenced in {source} is not in the secret "
                "store; add it via `lemma connector set-secret` or remove the reference."
            )
            raise ValueError(msg)
        return secret_value

    def env_repl(match: re.Match[str]) -> str:
        name = match.group(1)
        env_value = os.environ.get(name)
        if env_value is None:
            msg = (
                f"Environment variable '{name}' referenced in {source} "
                f"is not set; either export it or remove the reference."
            )
            raise ValueError(msg)
        return env_value

    # Resolve ${secret:...} first so a literal env name like `secret` can't
    # shadow it, then the plain ${ENV_VAR} pass.
    value = _SECRET_REF_RE.sub(secret_repl, value)
    return _ENV_VAR_RE.sub(env_repl, value)
