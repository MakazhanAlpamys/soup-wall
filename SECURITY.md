# Security policy

## Report a vulnerability

Use GitHub's private [Report a vulnerability](https://github.com/MakazhanAlpamys/soup-wall/security/advisories/new) form. Please do not post an exploitable report in a public issue. Include the affected version or commit, configuration, steps to reproduce, expected and observed result, and a minimal proof of concept where possible. We aim to acknowledge reports within a few days.

## Scope

We welcome reports about:

- Agent action-policy bypasses, approval grants that authorize a different call, MCP manifest attacks, or failures in guarded execution.
- Gateway inspection bypasses for a rule that should apply under the reported configuration, including fragmented streaming responses and completed tool calls.
- Authentication, authorization, cross-tenant or cross-workspace access, OIDC/SAML/SCIM validation, service-token handling, and session security.
- Prompt, response, credential, or identity-data exposure through logs, browser pages, exports, usage records, webhooks, or error responses.
- Request smuggling, SSRF, resource exhaustion, unsafe defaults, memory safety, or supply-chain issues in the Agent, Gateway, Console, and deployment examples.
- Material over-defense regressions that interrupt legitimate work.

When testing against a hosted instance, use only systems and accounts you own or have permission to test.

## Documented boundaries

- The Claude Code hook **fails open** if the Agent daemon is unavailable: after the hook timeout, the host proceeds. `agentfw preflight` detects an unavailable daemon; guarded execution owns the process boundary and fails closed.
- Agent enforcement starts in **shadow mode**. Gateway agent inspection and capability policy are off by default and shadow-first when enabled. A report should include the settings and policy that were active.
- The Gateway's default bind is loopback. A non-loopback bind requires proxy or tenant authentication; deploy a trusted HTTPS edge and protect the admin panel for remote use.
- The default detector uses signatures and heuristics. The optional ML stage requires separate model assets. Neither stage guarantees detection of adaptive attacks.
- Approval grants are scoped to one exact `ask` action. They do not defend against an attacker who already runs as the local operator and can read the daemon's key.
- On Unix, the Agent tightens an existing token file to mode `0600` when loading it. On Windows, the Agent does not yet set a user-only ACL on token or audit files; their protection depends on the profile directory ACL. Use a restricted profile directory on shared Windows hosts.
- The self-hosted identity implementation has local protocol tests, but real customer identity-provider interoperability has not been established. The constrained SCIM subset does not support every SCIM operation.
- Usage records and invoice previews are evidence for review, not final invoices or payment collection. Spend limits are request-admission controls.

These documented boundaries help describe the current threat model; regressions within them and unexpected consequences are still useful security reports.
