# Discoverability Gate

Status: `PASS` for pre-publication discoverability polish.

Run recorded: 2026-06-22.

## Reviewed Artifacts

- `README.md`: title and first paragraph name the exact problem, target users, and natural search terms: browser-to-localhost security checks, local AI agents, MCP servers, localhost MCP security, AI agent security, WebSocket control planes, and WebSocket `Origin`.
- `README.md`: quickstart, fixture examples, limitations, and comparison sections include developer search phrases around malicious websites connecting to local MCP servers, local AI agent ports, WebSocket Origin enforcement, localhost port scanners, MCP security scanners, and local agent discovery.
- `pyproject.toml`: package name, description, keywords, and classifiers use accurate category and problem terms without claiming adoption.
- `RELEASE_NOTES.md`: planned release title and notes describe the v0.1.0 scope, validation, limitations, and safety boundary.
- `DEMAND_EVIDENCE.md`, `VALIDATION_RESULTS.md`, and `BENCHMARK_RESULTS.md`: evidence, validation, and benchmark claims are linked to concrete public sources and reproducible local artifacts.

## Planned GitHub Repository Metadata

Repository name:

```text
loopback-litmus
```

Repository description:

```text
Safe browser-to-localhost security checks for local AI agent and MCP control planes.
```

Topics:

```text
mcp
mcp-security
ai-agent-security
localhost-security
browser-security
websocket-security
websocket-origin
developer-tools
python
security-tools
```

These topics describe the actual product surface. They should not be expanded with unrelated security, AI, or scanner terms.

## Planned Package Metadata

Package name:

```text
loopback-litmus
```

Package description:

```text
Safe browser-to-localhost reachability checks for local AI agent and MCP control planes.
```

Primary package search terms:

- `mcp security`
- `localhost security`
- `browser localhost`
- `websocket origin`
- `ai agent security`
- `local agent scanner`

## Planned Release Metadata

Release title:

```text
loopback-litmus v0.1.0 - browser-to-localhost checks for local AI/MCP control planes
```

Release notes source:

- `RELEASE_NOTES.md`

## Distribution Plan

Concrete launch/search surfaces:

- GitHub repository search through name, description, README, topics, and release notes.
- PyPI package search through package name, description, classifiers, and keywords.
- `uvx`/`pipx` usage once the package is available on PyPI.
- Security and MCP developer communities discussing local MCP server exposure, browser-to-localhost attacks, WebSocket Origin validation, and MCP security scanners.
- Advisory-faithful fixture demos that show before/after behavior without running historical vulnerable products or exploit payloads.

No traction, users, maintainer interest, downloads, stars, or adoption are claimed.

## Gate Result

Discoverability: `PASS`.

Reason: the concrete README, package metadata, planned GitHub metadata, release notes, limitations, comparison, and distribution plan now use accurate category and problem terms that developers would search when they need a local browser-to-localhost security check for AI agent or MCP control planes.
