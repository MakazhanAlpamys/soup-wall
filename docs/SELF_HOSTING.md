# Self-host Soup Wall

This guide covers the source distribution of Soup Wall Agent, Gateway, and Console. All three are Apache-2.0 code in one workspace. There is no Soup Wall license server or required Soup Wall account. You still need credentials and an account with any model provider you choose to call.

Commands below use a POSIX shell and start in the repository root. Use the equivalent environment-variable syntax on Windows.

## 1. Build and inspect the local defaults

```sh
cargo build --locked --release --workspace
./target/release/llm-firewall preflight
```

The Gateway reads `firewall.yaml` and `policies/default.yaml` relative to its working directory. The checked-in configuration binds to `127.0.0.1:8080`, with `proxy_auth`, `tenant_store`, shared Redis limits, agent inspection, and capability policy disabled. `preflight` checks configuration, policy, and local security requirements without opening the HTTP listener or connecting to external services.

The proxy executable still has the established name `llm-firewall`. Existing `LLM_FW_*` variables, HTTP headers, and stored identifiers remain valid for compatibility under the Soup Wall brand. For an existing installation, follow the [upgrade guide](UPGRADING.md) before replacing a binary or image.

## 2. Start the Gateway

```sh
./target/release/llm-firewall
```

In another terminal:

```sh
curl -f http://127.0.0.1:8080/healthz
```

For OpenAI SDK clients, use `http://127.0.0.1:8080/v1` as the base URL. The Gateway accepts `/v1/chat/completions` and `/v1/responses`. For the native Anthropic Messages API, use `http://127.0.0.1:8080` and `/v1/messages`. The client can keep sending its provider authorization header, which the Gateway forwards upstream. A local server-side OpenAI fallback key is optional through `LLM_FW_OPENAI_API_KEY` or `OPENAI_API_KEY`.

For example, after setting `OPENAI_API_KEY` in your shell, replace the model placeholder with one available to your provider account:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"YOUR_AVAILABLE_MODEL","messages":[{"role":"user","content":"Hello"}]}'
```

This request contacts the configured provider and can incur provider charges. The health and preflight commands above do not make a model request.

## 3. Add a local operator Console

Edit `firewall.yaml`:

```yaml
tenant_store:
  enabled: true
  backend: sqlite
  database_path: data/llm-firewall.sqlite
  admin_token_env: LLM_FW_ADMIN_TOKEN
```

Set `LLM_FW_ADMIN_TOKEN` to a long random value in the environment or a local, ignored `.env` file. Do not put the token in YAML or version control. Run `llm-firewall preflight` again, start the Gateway, then open `http://127.0.0.1:8080/admin`. The operator panel keeps the entered token in that browser tab's memory and lets authorized administrators create tenants, issue and revoke client tokens, configure model/rate/spend limits, and inspect privacy-safe audit outcomes.

`proxy_auth` and `tenant_store` are mutually exclusive. The first uses one shared Gateway token sent in `X-LLM-Firewall-Token`; the second issues tenant-scoped client tokens and separately protects `/admin/v1/*` with `X-LLM-Firewall-Admin-Token`. Keep provider credentials distinct from either Gateway token.

The customer panel at `/customer` requires an active organization, workspace membership, and configured OIDC or SAML sign-in. There is no local password login. The code includes an organization-scoped SCIM `/Users` and `/Groups` subset, but provisioning does not automatically grant workspace authority. Validate the chosen IdP and the supported SCIM operations with a real integration before customer use.

## 4. Plan a networked deployment

The local SQLite mode is for one instance. For multiple Gateway replicas, configure PostgreSQL as the control-plane store and run `llm-firewall migrate` with a migration database role before starting runtime replicas. Use a separate least-privileged runtime role. Shared Redis is optional for cross-replica rate and spend admission windows; it is not the immutable usage ledger. Review the deployment templates under `deploy/` and run their checks for your chosen environment.

A non-loopback bind requires `proxy_auth` or `tenant_store`. Put a trusted HTTPS edge in front of remote traffic, restrict the admin and metrics routes, keep provider and identity secrets in a secret manager, and verify `/readyz` as well as `/healthz`. Treat OIDC, SAML, SCIM, backup/restore, and alerting as deployment acceptance work; local fixtures alone do not prove a production integration.

## 5. Understand the data paths

| Component | Network and state |
| --- | --- |
| Agent daemon | Local hook API, local token and JSONL audit under `~/.agentfw`. No Soup Wall telemetry upload. An MCP server or user-configured local judge has its own behavior. |
| Gateway | Calls the configured OpenAI or Anthropic upstream when a client requests a model. May use a client-supplied provider key or an optional server-side key. |
| Console | Uses the Gateway's tenant store. Optional OIDC/SAML sign-in contacts your IdP; optional webhooks contact destinations you configure. |
| Shared operations | PostgreSQL and Redis are optional deployment services with distinct roles. `/healthz` tests liveness; `/readyz` reflects selected dependency and audit readiness. |

The Gateway records outcomes and privacy-safe usage evidence without intentionally storing prompt or response bodies in its normal audit path. Review your own edge, provider, database, Redis, and identity-provider logging policies as part of deployment.

## Enforcement and billing limits

The Agent daemon starts in shadow mode. Its Claude Code hook fails open when the daemon is unavailable, so run `agentfw preflight` before sessions that depend on it. Guarded execution has a separate fail-closed process boundary and its shell sandbox requires Linux/bubblewrap.

The Gateway's model traffic policy is independent of its opt-in `agent_inspection` and `capability_policy`. Those agent controls default to off and start shadow-first when enabled. `fail_mode: fail_closed` governs the Gateway's configured proxy failure behavior; review individual streaming and provider cases before promising complete enforcement.

Spend limits reserve an operator-priced amount at request admission. They are not an invoice. Tenant-authenticated traffic can produce immutable usage events, reconciliation evidence, quotas, retention history, and a read-only USD invoice preview. A preview is always non-final; missing token, price, or provider evidence is flagged for review. Final invoices, credits, refunds, tax calculation, and payment collection are not implemented.

See [SECURITY.md](../SECURITY.md) for the threat boundary and private reporting route, and [docs/methodology.md](methodology.md) for benchmark limits.
