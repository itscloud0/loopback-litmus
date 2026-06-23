# Evaluation Plan

## Central Claim

`loopback-litmus` should identify browser-reachable local AI agent and MCP control-plane risk faster and more safely than manual `lsof` plus ad hoc `curl`/WebSocket checks, without executing exploit payloads or starting untrusted MCP servers.

## Primary Evaluation

Build a fixture suite and real-world validation set.

Current validation results are recorded in `VALIDATION_RESULTS.md`.
Current benchmark results are recorded in `BENCHMARK_RESULTS.md`.

Fixture requirements:

- at least one HTTP service with unauthenticated metadata exposure
- at least one WebSocket service that accepts hostile Origin headers
- at least one WebSocket service that rejects hostile Origin headers
- at least one MCP-like HTTP endpoint that responds to unauthenticated `initialize`
- at least one hardened MCP-like endpoint requiring auth
- loopback-only and all-interface bind variants

Real-world case requirements before publication:

- at least three unrelated public advisory patterns
- at least two ecosystems, with Node and Python first
- no vulnerable product is run with real credentials or real cluster access
- any case using an actual historical vulnerable version runs inside a disposable container or VM
- otherwise use faithful local fixtures derived from public advisory behavior

Candidate real-world/advisory cases:

- MCP Inspector CVE-2025-49596 style local proxy exposure.
- Claude Code IDE extension CVE-2025-52882 style unauthenticated localhost WebSocket.
- Kubectl MCP Server CVE-2025-65719 style browser-to-localhost MCP control-plane reachability.
- OpenClaw ClawJacked style missing Origin/rate-limit/device-pairing trust.
- GPT Researcher `/ws` MCP config exposure, modeled without command execution.

Completed advisory-faithful fixture validation:

- `advisory-mcp-inspector-open`: safe MCP Inspector proxy pattern, expected `HIGH`.
- `advisory-claude-ide-ws-open`: safe Claude IDE WebSocket pattern, expected `HIGH`.
- `advisory-kubectl-mcp-open`: safe Kubectl MCP control-plane pattern, expected `HIGH`.
- `advisory-gpt-researcher-ws-open`: safe Python `/ws` exposure pattern, expected `HIGH`.

## Baseline

Manual baseline:

```bash
lsof -iTCP -sTCP:LISTEN -n -P
curl -i http://127.0.0.1:<port>/
use a WebSocket client against ws://127.0.0.1:<port>
```

Compare against:

- LocalPortScan-style open-port discovery.
- A generic `nmap -sT 127.0.0.1` scan.
- Manual OWASP WebSocket Origin testing.

Completed benchmark:

- `BENCHMARK_RESULTS.md` compares one `loopback-litmus scan --ports ... --json` run against the documented manual-equivalent workflow.
- The benchmark covers four unsafe advisory-faithful fixtures, two hardened controls, and three ordinary local developer-server samples.
- Current result: `PASS` with 4/4 unsafe true positives, 2/2 hardened true negatives, 0/3 ordinary dev-server high/medium false positives, and 27 manual-equivalent commands replaced.

## Metrics

Detection:

- true-positive rate on unsafe fixture services
- true-negative rate on hardened fixture services
- bind-address classification accuracy
- process/port attribution accuracy
- MCP endpoint detection precision

Safety:

- zero command execution probes
- zero mutating requests by default
- no reads of `.env` or secret-looking files
- no public-network scanning by default
- explicit warning for non-loopback targets

Workflow:

- time to first useful report
- number of manual commands replaced
- clarity of remediation output
- JSON schema stability

Engineering:

- unit tests for parser, probes, classifiers, and renderers
- integration tests for fixture servers
- macOS and Linux CI where practical
- documented unsupported platforms

## Expected v0.1 Result

`loopback-litmus scan` should produce:

- a concise terminal report
- JSON output with stable fields
- a reproducible evidence section per risky service
- remediation notes mapped to Host, Origin, auth, bind address, and MCP initialization behavior

## Known Weaknesses

- Process attribution differs across macOS and Linux.
- Some services intentionally expose unauthenticated local APIs; risk depends on capabilities.
- A safe probe can prove reachability and weak gates, but cannot prove full exploitability.
- Browser behavior changes over time, especially around Private Network Access and 0.0.0.0.
- Local port scanners can be noisy; the product must avoid looking like a generic checker.

## Reproducible Commands

Planned v0.1 commands:

```bash
python3 -m loopback_litmus scan
python3 -m loopback_litmus scan --json
python3 -m loopback_litmus serve-fixture --case websocket-no-origin
python3 -m loopback_litmus serve-fixture --case mcp-unauth-initialize
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 scripts/benchmark.py --output BENCHMARK_RESULTS.md
```

## Stop Or Reposition Criteria

Stop or reposition if:

- validation does not beat manual `lsof` plus generic port scanning
- risk classification produces too many false positives on ordinary dev servers
- meaningful proof requires unsafe payloads
- existing scanners ship equivalent local browser-reachability evidence first
- real users ask for enterprise inventory instead of a local developer CLI
