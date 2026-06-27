# loopback-litmus: browser-to-localhost security checks for local AI agents and MCP servers

`loopback-litmus` is a local CLI for developers, AI tool authors, and security engineers who need a safe browser-to-localhost security check for local AI agent, MCP server, IDE helper, and WebSocket control-plane services running on their workstation.

It is not a generic vulnerability scanner or exploit tool. The first version focuses on safe evidence for localhost MCP security and AI agent security reviews: loopback/all-interface binds, unauthenticated HTTP metadata, WebSocket handshakes that accept hostile `Origin` headers, and MCP-style `initialize` responses without credentials.

## Quickstart

Requires Python 3.11 or newer.

From a checkout:

```bash
PYTHONPATH=src python3 -m loopback_litmus scan
PYTHONPATH=src python3 -m loopback_litmus scan --port 18789
PYTHONPATH=src python3 -m loopback_litmus scan --known-agent-ports --json
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case websocket-no-origin --port 18789
```

When installed as a Python package:

```bash
python3.11 -m pip install .
loopback-litmus scan
loopback-litmus scan --json
```

## What It Checks

- Listening loopback and all-interface TCP services on macOS and Linux.
- Browser-origin HTTP reachability using safe `GET /` requests.
- WebSocket `Origin` enforcement with a synthetic hostile origin.
- MCP-like unauthenticated HTTP `initialize` exposure.
- Basic process and known-port hints for AI agent and MCP developer tools.
- Text and JSON reports with concrete evidence and remediation notes.

## Fixture Examples

Use fixtures for before/after localhost security tests, MCP security scanner comparisons, WebSocket Origin validation demos, and CI validation:

```bash
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case http-metadata-open --port 18780
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case websocket-no-origin --port 18781
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case websocket-origin-enforced --port 18782
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case mcp-unauth-initialize --port 18783
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case mcp-auth-required --port 18784
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case advisory-mcp-inspector-open --port 18785
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case advisory-claude-ide-ws-open --port 18786
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case advisory-kubectl-mcp-open --port 18787
PYTHONPATH=src python3 -m loopback_litmus serve-fixture --case advisory-gpt-researcher-ws-open --port 18788
```

Then scan a fixture:

```bash
PYTHONPATH=src python3 -m loopback_litmus scan --port 18781
```

The advisory fixtures are safe models of public vulnerability patterns. They prove detection of missing WebSocket `Origin` enforcement and unauthenticated MCP-style `initialize` reachability without launching real vulnerable products, executing commands, or sending exploit payloads.

## Example Reports To Look For

These examples cover the first developer searches this tool is meant to answer:

- "Can a malicious website connect to my local MCP server?"
- "Which local AI agent ports accept browser-origin WebSocket connections?"
- "Do my localhost MCP tools require authentication before initialize?"
- "How do I test WebSocket Origin enforcement on a local agent service?"

## Limitations

- A safe probe can prove browser-style reachability and weak gates, not full exploitability.
- The tool does not execute MCP configs, call MCP tools, run shell commands through services, or send exploit payloads.
- Process attribution depends on platform tools such as `lsof` or `ss`, and those tools can omit process or PID details when permissions are limited.
- Public-network scanning is intentionally not a default workflow.
- Some local developer servers intentionally expose unauthenticated APIs; risk depends on capability.
- It does not replace MCP config security scanners, skill scanners, enterprise endpoint inventory, or product-specific CVE remediation.

## Process Attribution Notes

Listener discovery is intentionally conservative:

- macOS uses `lsof -nP -iTCP -sTCP:LISTEN` when available.
- Linux uses `ss -H -ltnp` when `lsof` is unavailable.
- `0.0.0.0`, `*`, and `[::]` are treated as all-interface binds and scanned through `127.0.0.1`.
- Missing process or PID fields are reported as unknown instead of guessed.

## Comparison

- Browser localhost port scanners find open ports. `loopback-litmus` adds AI/MCP hints, WebSocket `Origin` evidence, MCP initialization checks, and remediation text.
- MCP security scanners inspect MCP configs, tools, prompts, or remote URLs. `loopback-litmus` checks already-running local services and avoids executing untrusted MCP configuration.
- Manual `lsof`, `curl`, and WebSocket clients can test localhost ports, but they do not produce a repeatable browser-to-localhost risk report for AI agent and MCP control planes.
- Enterprise local-agent discovery can inventory managed endpoints. `loopback-litmus` is a local open-source developer check with fixture-backed evidence and no hosted backend.

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 scripts/benchmark.py --output BENCHMARK_RESULTS.md
```
