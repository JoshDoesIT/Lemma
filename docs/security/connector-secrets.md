# Connector Credentials: Storage, Rotation, and Incident Response

Connectors authenticate to upstream systems (GitHub, Jira, ServiceNow, cloud
providers, …) with API tokens, PATs, or client secrets. This page documents
how Lemma stores those credentials, how to rotate them, and what to do when
one leaks.

## Where credentials can live

Lemma keeps a connector credential out of your connector code and out of git.
A credential can come from the environment or from a **secret backend**, both
referenced inside `lemma_connector_config.yaml`:

| Source | Reference in config | When to use |
|--------|--------------------|-------------|
| **Environment variable** | `${ENV_VAR}` | CI runners and orchestrators that already inject secrets as env vars. |
| **Secret backend** | `${secret:NAME}` | Anywhere you'd rather not export the credential into the process environment. The *backend* behind `${secret:NAME}` is selectable (see below) — local encrypted store by default, or Vault / AWS Secrets Manager / OS keyring. |

Both are resolved at config-load time. A missing env var or missing stored
secret raises a clean error rather than silently substituting an empty string.

The key property: `${secret:NAME}` is **backend-agnostic**. Switching from the
local store to Vault (or AWS Secrets Manager, or the OS keyring) is a one-line
environment change — `LEMMA_SECRET_BACKEND` — and never touches the config
file's `${secret:NAME}` references. See [Remote secret
backends](#remote-secret-backends).

## The encrypted secret store

`lemma connector set-secret NAME` writes to `.lemma/secrets.json`:

- The whole `{name: value}` map is encrypted with **Fernet** (AES-128-CBC +
  HMAC-SHA256). The key is derived with **PBKDF2-HMAC-SHA256** (600k
  iterations) from the passphrase in `LEMMA_SECRET_PASSPHRASE` over a random
  per-write salt. Neither secret names nor values appear in plaintext on disk.
- The file is written with `0600` (owner read/write only).
- The secret **value** is never passed as a CLI argument — it comes from
  `LEMMA_SECRET_VALUE` or a hidden interactive prompt, so it can't leak into
  shell history or a process listing.

```bash
export LEMMA_SECRET_PASSPHRASE='…'          # unlocks the store
lemma connector set-secret JIRA_TOKEN        # prompts (hidden) for the value
lemma connector list-secrets                 # names only
```

```yaml
# lemma_connector_config.yaml
connector: jira
config:
  base_url: https://acme.atlassian.net
  email: ${JIRA_EMAIL}        # from the environment
  token: ${secret:JIRA_TOKEN} # from the encrypted store
```

## Remote secret backends

For hosts where credentials should live in a central secret manager rather than
a local file, set `LEMMA_SECRET_BACKEND` to source `${secret:NAME}` from a
remote backend instead. The config file is unchanged — only the environment of
the process running `lemma connector run` / `lemma evidence collect --config`
differs.

| `LEMMA_SECRET_BACKEND` | Backend | Extra install |
|------------------------|---------|---------------|
| _(unset)_ / `local` | Encrypted file store (default) | — |
| `vault` | HashiCorp Vault (KV v2) | `pip install 'lemma[secrets]'` |
| `aws-secrets-manager` | AWS Secrets Manager | — (boto3 ships with Lemma) |
| `keyring` | OS keyring (Keychain / Secret Service / Credential Manager) | `pip install 'lemma[secrets]'` |

Remote backends are **read-only sources**: Lemma resolves `${secret:NAME}` from
them but never writes to them. Create and rotate those secrets with the
backend's own tooling (`vault kv put`, the AWS console/CLI, your OS keychain).
The `lemma connector set-secret` / `list-secrets` / `rm-secret` commands manage
the local store only.

Every backend reads from one configurable location holding a `{name: value}`
namespace, so `${secret:JIRA_TOKEN}` maps to the `JIRA_TOKEN` entry regardless
of backend.

### HashiCorp Vault

```bash
export LEMMA_SECRET_BACKEND=vault
export VAULT_ADDR='https://vault.example:8200'
export VAULT_TOKEN='s.xxxxx'                  # or any auth hvac picks up
export LEMMA_VAULT_MOUNT='secret'             # KV v2 mount (default: secret)
export LEMMA_VAULT_PATH='lemma/connectors'    # path holding the secret map
# vault kv put secret/lemma/connectors JIRA_TOKEN=…
```

`${secret:JIRA_TOKEN}` reads key `JIRA_TOKEN` from the KV v2 secret at
`LEMMA_VAULT_MOUNT/LEMMA_VAULT_PATH`.

### AWS Secrets Manager

```bash
export LEMMA_SECRET_BACKEND=aws-secrets-manager
export AWS_REGION='us-east-1'
export LEMMA_AWS_SECRET_ID='lemma/connectors' # one secret, JSON {name: value}
# aws secretsmanager put-secret-value --secret-id lemma/connectors \
#   --secret-string '{"JIRA_TOKEN":"…"}'
```

Credentials use boto3's default chain (env vars, profile, instance role).
`${secret:JIRA_TOKEN}` reads the `JIRA_TOKEN` key from the JSON document in the
`LEMMA_AWS_SECRET_ID` secret.

### OS keyring

```bash
export LEMMA_SECRET_BACKEND=keyring
export LEMMA_KEYRING_SERVICE='lemma-connectors'   # default
# keyring set lemma-connectors JIRA_TOKEN
```

`${secret:JIRA_TOKEN}` reads the password stored under service
`LEMMA_KEYRING_SERVICE`, username `JIRA_TOKEN`, from the platform keyring.

### Per-backend threat model

The backend choice moves *where the credential lives and who can read it*; it
does not change the fact that Lemma uses the credential only in upstream auth
headers and never writes it to the evidence log.

| Backend | Trust anchor | What a Lemma-host compromise exposes | Notes |
|---------|--------------|--------------------------------------|-------|
| **Local store** | `LEMMA_SECRET_PASSPHRASE` (not on disk) | The passphrase in env/memory ⇒ every stored secret. | Best when there's no central manager; see the [threat model](#threat-model) below. |
| **Vault** | `VAULT_TOKEN` + Vault policy | Read access to exactly the configured KV path, for the token's TTL. | Scope the token's policy to the one path; short TTLs + Vault's audit log bound and record exposure. Lemma never holds a root token. |
| **AWS Secrets Manager** | IAM identity of the host | `secretsmanager:GetSecretValue` on the configured secret only, if the role allows it. | Grant `GetSecretValue` on the single `LEMMA_AWS_SECRET_ID` ARN — not `*`. CloudTrail records each read. |
| **OS keyring** | Local OS user session | Whatever the unlocked keychain grants the user — typically all entries for that user. | Strongest on a single trusted workstation; weakest for shared/headless hosts where the keyring may be unlocked for any process the user runs. |

Because remote backends are read-only to Lemma, a compromised Lemma host can
read the secrets it's pointed at but cannot delete or overwrite them in the
backend, and cannot reach secrets outside the configured path/secret/service.
Scope the backend credential (Vault policy, IAM statement) to exactly the one
location Lemma needs.

## Threat model

This section covers the **local encrypted store**; per-backend trade-offs for
remote backends are in the [table above](#per-backend-threat-model).

What the encrypted store **does** protect against:

- **Accidental git commit / backup leak of `.lemma/`.** A stolen
  `secrets.json` is useless without `LEMMA_SECRET_PASSPHRASE`; the passphrase
  is never written to disk by Lemma.
- **Casual disk / repo browsing.** Secret names and values are ciphertext;
  `0600` keeps other local users out.
- **Token leakage into evidence.** Connectors send credentials only in
  request auth headers — credentials are never written into the OCSF events
  or the signed evidence log. This is covered by a regression spot-check.

What it does **not** protect against (out of scope for this layer):

- An attacker who has **both** `secrets.json` and the passphrase (or the live
  process memory). Protect the passphrase with the same care as any root
  secret; prefer a [remote backend](#remote-secret-backends) (Vault / AWS
  Secrets Manager / keyring) for high-value hosts so the credential never lives
  on the Lemma host at all.
- A **compromised upstream** that issued the token, or a malicious connector.
- Passphrase brute-force if the passphrase is weak. Use a long, random
  passphrase; PBKDF2 at 600k iterations raises the cost but is not a
  substitute for entropy.

## Rotation

Rotation is overwrite-in-place and requires **no service restart**: each
`lemma evidence collect` run re-reads the store, so the next run after a
rotation uses the new value.

```bash
lemma connector set-secret JIRA_TOKEN   # re-running an existing name rotates it
```

Recommended cadence: rotate connector tokens on the same schedule as your
other CI/service credentials (commonly 90 days), and immediately on any
suspicion of exposure (see below).

## Incident response: a leaked connector token

1. **Revoke at the source first.** Delete/disable the token in the upstream
   system (GitHub PAT settings, Jira API tokens, the cloud IAM console). This
   is the only step that actually stops the attacker — everything else is
   cleanup. Upstream revocation makes the next collect attempt fail loudly
   rather than silently succeed with a stale credential.
2. **Mint a replacement** upstream and store it: `lemma connector set-secret
   <NAME>` (or update the env var in your orchestrator). Because rotation is
   restart-free, the next scheduled collect picks it up.
3. **Rotate the store passphrase if it may also be exposed.** If
   `LEMMA_SECRET_PASSPHRASE` could have leaked alongside `secrets.json`,
   choose a new passphrase, re-`set-secret` every entry under it, and treat
   the old file as compromised.
4. **Check the evidence log for the exposure window.** Use `lemma evidence`
   to review what was collected with the leaked credential; the hash-chained,
   signed log lets you bound the window precisely. Connector tokens are not
   written into the log, so the log itself does not need scrubbing — but it is
   your timeline of what the credential touched.
5. **Confirm cleanup.** Re-run the affected connector and verify it
   authenticates with the new credential and appends fresh evidence.

## See also

- [`lemma connector` secret commands](../reference/index.md#lemma-connector)
- [Evidence log and signing](../reference/index.md#lemma-evidence)
