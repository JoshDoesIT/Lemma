# Connector Credentials: Storage, Rotation, and Incident Response

Connectors authenticate to upstream systems (GitHub, Jira, ServiceNow, cloud
providers, …) with API tokens, PATs, or client secrets. This page documents
how Lemma stores those credentials, how to rotate them, and what to do when
one leaks.

## Where credentials can live

Lemma supports two homes for a connector credential, both keeping it out of
your connector code and out of git:

| Backend | Reference in config | When to use |
|---------|--------------------|-------------|
| **Environment variable** | `${ENV_VAR}` | CI runners and orchestrators that already inject secrets as env vars. |
| **Encrypted secret store** | `${secret:NAME}` | Workstations and long-lived hosts where you want credentials encrypted at rest rather than exported into the process environment. |

Both are resolved at config-load time (`lemma_connector_config.yaml`). A
missing env var or missing stored secret raises a clean error rather than
silently substituting an empty string.

> **Pluggable remote backends** (OS keyring, HashiCorp Vault, AWS Secrets
> Manager) are intentionally deferred. The encrypted file store is the local
> canonical store those backends will slot behind without changing the
> `${secret:NAME}` reference syntax.

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

## Threat model

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
  secret; prefer a real KMS/keyring backend (deferred) for high-value hosts.
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
