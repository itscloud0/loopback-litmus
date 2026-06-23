# loopback-litmus v0.1.0 - browser-to-localhost checks for local AI/MCP control planes

Initial private-first release candidate for `loopback-litmus`, a local Python CLI that checks whether browser-origin requests can reach local AI agent, MCP server, IDE helper, and WebSocket control-plane services.

## Included

- `loopback-litmus scan` for local loopback/all-interface listener checks.
- Safe HTTP metadata probes, hostile-Origin WebSocket handshakes, and unauthenticated MCP-style `initialize` probes.
- Text and JSON reports with risk class, evidence, and remediation notes.
- Fixture servers for unsafe and hardened HTTP, WebSocket, MCP, and advisory-faithful local-control-plane patterns.
- Unit and fixture integration tests.
- Reproducible benchmark script comparing one scan against manual `lsof`/HTTP/WebSocket/MCP initialize checks.

## Validation

- Advisory-faithful fixtures model MCP Inspector CVE-2025-49596, Claude Code IDE extension CVE-2025-52882, Kubectl MCP Server CVE-2025-65719, and GPT Researcher `/ws` exposure without command execution or exploit payloads.
- Current benchmark result: 4/4 unsafe fixtures classified `HIGH`, 2/2 hardened controls classified `LOW`, and 0/3 ordinary local dev-server samples classified `HIGH` or `MEDIUM`.

## Limitations

- Safe probes prove browser-style reachability and weak gates, not full exploitability.
- The CLI does not execute MCP configs, call MCP tools, run commands through services, read secrets, or scan public-network targets by default.
- Process attribution depends on platform tools such as `lsof` or `ss`.

## Install

Source checkout:

```bash
PYTHONPATH=src python3 -m loopback_litmus scan
```

Package install command will be added after PyPI publication.
