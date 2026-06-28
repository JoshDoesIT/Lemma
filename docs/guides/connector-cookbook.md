# Connector Development Cookbook

Recipes for authors building production connectors, distilled from Lemma's
first-party connectors (GitHub, Okta, AWS, Jira, ServiceNow, Azure DevOps,
Azure, PagerDuty). If you haven't written a connector yet, start with
[Build Your First Connector](build-your-first-connector.md); this page is the
reference you reach for once you're integrating a real upstream API.

Every recipe here follows three rules the first-party connectors hold to:

1. **Fail loud at construction, not mid-collect.** Validate required
   credentials in `__init__` so a misconfiguration surfaces immediately
   rather than as a cryptic 401 halfway through a run.
2. **Inject the HTTP client.** Take `client: httpx.Client | None = None` so
   tests can pass a `MockTransport` and CI never touches the real API.
3. **Emit typed OCSF events.** Construct `ComplianceFinding` (or another
   `OcsfBaseEvent` subclass) directly — the Pydantic model is the schema
   gate.

## Authentication patterns

Pick the idiomatic credential for the platform and read it from a constructor
arg **or** an environment variable, preferring the arg.

### Bearer token

```python
self._token = token or os.environ.get("LEMMA_ACME_TOKEN") or None
if not self._token:
    raise ValueError(
        "AcmeConnector requires a token. Set LEMMA_ACME_TOKEN or pass token=..."
    )

def _headers(self) -> dict[str, str]:
    return {"Accept": "application/json", "Authorization": f"Bearer {self._token}"}
```

Used by the GCP (`Bearer <access_token>`) and Okta (`SSWS <token>`)
connectors. Okta is the same shape with a platform-specific scheme prefix.

### HTTP Basic (email/token or user/password)

```python
import base64

def _auth_header(self) -> str:
    creds = f"{self._email}:{self._token}".encode()
    return "Basic " + base64.b64encode(creds).decode()
```

Used by Jira (`email:api_token`) and ServiceNow (`username:password`). Azure
DevOps is the special case of Basic with an **empty username** and the PAT as
the password: `base64(":" + pat)`.

### OAuth2 client-credentials

When the platform issues short-lived access tokens, exchange a client secret
for a token once and cache it per scope on the connector instance:

```python
def _token_for(self, scope: str) -> str:
    if scope in self._token_cache:
        return self._token_cache[scope]
    resp = self._client.post(self._token_url, data={
        "grant_type": "client_credentials",
        "client_id": self._client_id,
        "client_secret": self._client_secret,
        "scope": scope,
    })
    if not resp.is_success:
        raise ValueError(f"Token endpoint refused credentials (HTTP {resp.status_code}).")
    token = resp.json()["access_token"]
    self._token_cache[scope] = token
    return token
```

Used by the Azure connector, which negotiates two scopes (Microsoft Graph and
Resource Manager) and hits the token endpoint at most once per scope per run.

### Provider credential chains

Some SDKs resolve credentials themselves (env vars, profile, instance
metadata). The AWS connector leans on boto3's default chain rather than a
Lemma-specific variable — but still fails loud at construction if no
credentials resolve, so the error lands before any API call.

### Storing the credential

Never hard-code or commit a token. Operators supply it via an environment
variable or the encrypted [secret store](../security/connector-secrets.md);
in `lemma_connector_config.yaml` they reference it as `${ACME_TOKEN}` or
`${secret:ACME_TOKEN}`. Your connector only ever sees the resolved string.

## Rate-limit handling

Treat HTTP 429 as a clean, named error rather than letting a downstream
`response.json()` explode on an unexpected body:

```python
def _get(self, path: str) -> httpx.Response:
    resp = self._client.get(path, headers=self._headers())
    if resp.status_code == 429:
        raise ValueError(
            f"Acme API rate-limit exceeded while fetching {path}. "
            "Retry after the quota resets."
        )
    return resp
```

Every first-party connector raises `ValueError` naming the endpoint on 429.
Naming the endpoint matters: an operator seeing `serviceAccounts` vs `sinks`
in the message knows which call to back off. Lemma deliberately does **not**
auto-retry inside the connector — retry/backoff is the scheduler's job (see
[`lemma connector run`](../reference/index.md#lemma-connector-run)), so a
single run stays fast and deterministic.

## Designing the dedupe key (`metadata.uid`)

The evidence log dedupes on `metadata.uid` within a single UTC day. A stable,
well-chosen UID means same-day re-runs (cron retries, manual reruns) collapse
to one entry instead of piling up duplicates.

Build the UID from the dimensions that make a finding **unique for the day**:

```python
uid = f"acme:{signal_type}:{account_id}:{datetime.now(UTC):%Y-%m-%d}"
```

Patterns from the first-party connectors:

| Connector | UID dimensions |
|-----------|----------------|
| AWS | `(event_type, account_id, UTC date)` |
| Okta | `(event_type, domain, UTC date)` |
| Jira / ServiceNow | `(site or instance, UTC date)` |
| Azure | `(tenant_id, subscription_id, signal_type, UTC date)` |
| GCP | `(signal_type, project_id, UTC date)` |

Rules of thumb:

- **Include the target identifier** (account, domain, project) so two
  environments don't collide.
- **Include `signal_type`** when one run emits multiple findings, so each is
  independently deduped.
- **Include the UTC date**, not a timestamp — you want one finding per day,
  not one per second.
- **Freeze the clock in tests** (monkeypatch the module's `datetime`) and
  assert two separate connector instances produce identical UIDs for the same
  day. That test is your dedupe contract.

## Multi-finding runs and `status_id`

A connector may emit several findings per run (the AWS and Azure connectors
emit three; GCP emits two). Each is its own `ComplianceFinding` with its own
UID. Map the platform's answer to the OCSF `status_id`:

| `status_id` | Meaning |
|-------------|---------|
| `1` | Pass — the control signal is present / satisfied. |
| `2` | Fail — records exist but the signal is absent. |
| `0` | Unknown — the upstream call failed or returned nothing to judge. |

Keep `0` distinct from `2`: "we couldn't tell" (API error, empty result) is
not the same as "we checked and it failed," and auditors treat them
differently.

## Testing with `MockTransport`

Inject an `httpx.Client` backed by a `MockTransport` so the suite drives the
connector end-to-end without a network:

```python
def _client(handler) -> httpx.Client:
    return httpx.Client(base_url="https://acme.example", transport=httpx.MockTransport(handler))

def test_emits_finding():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [...]})

    connector = AcmeConnector(account="acme", token="t", client=_client(handler))
    events = list(connector.collect())
    assert events[0].status_id == 1
```

Cover, at minimum: each required constructor field, the pass/fail/unknown
status branches, the 429 path, the auth header on the wire, and UID stability
across two same-day runs. Then validate the whole project with
[`lemma connector test`](../reference/index.md#lemma-connector-test).
