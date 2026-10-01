# Agent guarded execution

Soup Wall Agent can inspect a proposed tool call, but a verdict alone cannot
isolate a process. Use the guarded entry points when an agent must actually
execute a command, change a workspace file, or fetch a URL. The normal Claude
Code hook remains a decision and audit layer and fails open if its daemon is
unavailable; run `agentfw preflight` before a session that depends on it.

## Guarded commands and files

```sh
agentfw guarded-shell --workspace ./checkout -- 'make test'
agentfw guarded-write --workspace ./checkout --path notes/result.txt --content generated
agentfw guarded-delete --workspace ./checkout --path notes/result.txt
agentfw guarded-rename --workspace ./checkout --from notes/a.txt --to notes/b.txt
```

`guarded-shell` inspects the exact Bash command and starts the sandbox only
after an explicit local `Allow`. `Ask`, `Deny`, and unresolved `Escalate` do not
create a process. The standalone `agentfw sandbox --workspace ./checkout --
sh -c 'make test'` command provides isolation without the guarded policy
decision; use `guarded-shell` for agent initiated shell work.

The typed file commands inspect the requested path and content before
mutation. They stay below the canonical workspace, reject traversal and
symlink targets, and operate on regular files. They do not turn arbitrary
shell or filesystem APIs into guarded operations. A host that lets an agent
use another route to execute or write can bypass these entry points.

## Guarded retrieval

```sh
agentfw guarded-fetch --url https://github.com/example/project --proxy-url https://egress.example.test
```

The destination host must be explicitly allowed by policy. The command
requires a deployment owned HTTPS egress proxy, rejects URL credentials,
fragments and redirects, and bounds the UTF-8 response passed back to the
agent. Loopback HTTP is for tests. Configure and review the proxy itself
separately; this command does not claim to isolate all network access made by
other host tools.

## OS boundary and validation

On Linux the shell sandbox uses bubblewrap and user, process, IPC, UTS,
cgroup, and network namespaces. It drops capabilities, starts with a read-only
system runtime and no inherited environment, and mounts one writable
`/workspace`. Network access is denied by default. Output and duration are
bounded. Windows and unsupported hosts fail closed for shell execution.

The Linux positive-path test needs bubblewrap and usable unprivileged user
namespaces. When a runner lacks namespace support, that positive assertion is
skipped; refusal and unsupported-host checks still run. You can run the
disposable container proof with `pwsh scripts/container-sandbox-smoke.ps1`
on a Docker host. A local proof is not evidence that an unreviewed production
host, egress proxy, or alternate agent tool route is isolated.

See the [architecture guide](../ARCHITECTURE.md) for the decision paths and
the [self-hosting guide](../SELF_HOSTING.md) for deployment defaults.
