# Validation Results

Status: `PASS` for advisory-faithful fixture validation and fixture/manual workflow benchmark. Publication remains blocked as noted below.

Run recorded: 2026-06-22 15:09 Europe/Amsterdam.

## Scope

Validation used safe local fixtures derived from public advisory behavior. It did not run vulnerable product versions, use real credentials, touch a Kubernetes cluster, execute MCP configs, invoke tools, spawn commands through a service, or send exploit payloads.

## External Advisory Patterns

| Pattern | Source | Fixture | Ecosystem | Safe behavior modeled | Expected result |
| --- | --- | --- | --- | --- | --- |
| MCP Inspector CVE-2025-49596 style unauthenticated local proxy | https://www.tenable.com/blog/how-tenable-research-discovered-a-critical-remote-code-execution-vulnerability-on-anthropic and https://nvd.nist.gov/vuln/detail/CVE-2025-49596 | `advisory-mcp-inspector-open` | MCP Inspector / npm developer tool | HTTP metadata is visible and MCP-style `initialize` succeeds without auth. | `HIGH` |
| Claude Code IDE extension CVE-2025-52882 style unauthorized localhost WebSocket | https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/ and https://github.com/advisories/GHSA-9f65-56v6-gxw7 | `advisory-claude-ide-ws-open` | VS Code / JetBrains IDE extension | WebSocket upgrade accepts hostile browser `Origin`. | `HIGH` |
| Kubectl MCP Server CVE-2025-65719 style browser-to-localhost MCP control plane | https://www.ox.security/blog/cve-2025-65719-critical-rce-in-kubectl-mcp-server/ | `advisory-kubectl-mcp-open` | Kubernetes MCP server | MCP-style `initialize` succeeds without auth on a local control plane. | `HIGH` |
| GPT Researcher `/ws` MCP config exposure style unauthenticated WebSocket | https://github.com/assafelovic/gpt-researcher/issues/1694 | `advisory-gpt-researcher-ws-open` | Python web app | WebSocket upgrade accepts hostile browser `Origin`. | `HIGH` |

This covers at least three unrelated public cases and at least two ecosystems. The fourth case is included to keep one Python-derived validation path in scope.

## Hardened Controls

| Control fixture | Behavior | Expected result |
| --- | --- | --- |
| `websocket-origin-enforced` | Rejects hostile browser `Origin` with `403`. | `LOW` |
| `mcp-auth-required` | Rejects unauthenticated HTTP/MCP requests with `401`. | `LOW` |

## Reproducible Validation Command

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Verified on 2026-06-22: 9 tests passed.

The fixture tests assert that advisory fixtures classify as `HIGH`, hardened controls classify as `LOW`, JSON reports keep a stable safety shape, and the report declares `executes_commands: false`.

Parser coverage was hardened on 2026-06-27 with representative macOS `lsof` and Linux `ss` listener rows, including wildcard binds, IPv6 loopback binds, missing process attribution, and non-listening `ss` rows that should be ignored.

Live CLI smoke test also passed with these fixtures started together:

- `advisory-mcp-inspector-open`: reported `HIGH`.
- `advisory-claude-ide-ws-open`: reported `HIGH`.
- `advisory-kubectl-mcp-open`: reported `HIGH`.
- `advisory-gpt-researcher-ws-open`: reported `HIGH`.
- `websocket-origin-enforced`: reported `LOW`.
- `mcp-auth-required`: reported `LOW`.

## Baseline Comparison

Manual baseline:

```bash
lsof -iTCP -sTCP:LISTEN -n -P
curl -i http://127.0.0.1:<port>/
use a WebSocket client with a hostile Origin against ws://127.0.0.1:<port>
POST a JSON-RPC initialize payload to likely MCP paths
```

`BENCHMARK_RESULTS.md` records the completed fixture/manual workflow benchmark. In the current run, `loopback-litmus scan --ports <ports> --json` classified 4/4 unsafe advisory fixtures as `HIGH`, 2/2 hardened controls as `LOW`, and 3/3 ordinary local developer-server samples as `INFO`. The ordinary sample high/medium false-positive rate was 0/3.

The same run measured one `loopback-litmus` command against 28 manual-equivalent commands: one listener-discovery command plus per-port HTTP, WebSocket-Origin, and MCP-initialize checks. Local elapsed times were 0.051 seconds for `loopback-litmus` and 0.031 seconds for the manual-equivalent baseline. Treat timings as local workflow-order evidence, not a universal performance claim.

## Failures And Limits

- Validation proves browser-style reachability and weak gates, not full exploitability.
- Fixtures are advisory-faithful models, not historical vulnerable binaries.
- Kubectl and GPT Researcher fixtures intentionally omit command execution and cluster/file access.
- Ordinary local developer servers can be reachable without being security-relevant; product hints and remediation text must stay conservative.
- Process attribution can be unavailable when platform tools omit process or PID details; the report leaves those fields unknown rather than guessing.
- Browser Private Network Access and `0.0.0.0` behavior can change; future browser-harness validation should track that separately.

## Gate Status

- Advisory-fixture validation: `PASS`, citing the four fixtures and fixture tests above.
- Full benchmark: `PASS`, citing `BENCHMARK_RESULTS.md`.
- Discoverability: `PASS`, citing `DISCOVERABILITY.md`, `RELEASE_NOTES.md`, `README.md`, and `pyproject.toml`.
- Publication: `READY_FOR_PRIVATE_PUBLISH`; public release remains blocked by the public-repo cooldown until 2026-06-25 19:56 Europe/Amsterdam.
