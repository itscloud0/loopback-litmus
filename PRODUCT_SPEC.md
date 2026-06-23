# PRODUCT_SPEC: loopback-litmus

## User Persona

Developers, security engineers, and AI tool authors who run local AI agents, MCP servers, IDE helpers, browser automation servers, or other developer control planes on their workstation.

## Painful Problem

Local agent tooling often treats `localhost` as trusted. Modern browsing agents and normal browsers can still reach loopback HTTP and WebSocket services from untrusted pages. Recent incidents show that missing authentication, missing Origin checks, DNS rebinding gaps, or raw MCP stdio configuration can turn a local helper into remote code execution, file access, or cluster control.

Developers currently do not have a small, local, safe way to answer: "Could a malicious web page reach any AI agent or MCP control plane running on this machine right now?"

## Current Bad Workflow

1. Read a vulnerability article or CVE.
2. Manually inspect running processes with `lsof`, `netstat`, or Activity Monitor.
3. Guess which ports belong to agents, MCP servers, IDE helpers, or dev tools.
4. Try ad hoc `curl`, browser tabs, WebSocket clients, or nmap probes.
5. Manually reason about Origin, Host, authentication, and MCP handshakes.
6. Patch or stop services without a reproducible before/after report.

## Proposed Better Workflow

Run one local command:

```bash
loopback-litmus scan
```

The tool inspects loopback-bound HTTP and WebSocket services, identifies likely AI agent and MCP surfaces, runs safe browser-reachability and protocol probes, and emits a local report:

- running loopback services by port, protocol, process, and likely product
- whether a browser-origin request can connect
- whether WebSocket Origin is enforced
- whether unauthenticated HTTP/MCP metadata is exposed
- whether an MCP `initialize` probe succeeds without credentials
- whether the service binds to `127.0.0.1`, `localhost`, `::1`, or `0.0.0.0`
- risk class with concrete evidence and remediation hints
- JSON output for CI or endpoint inventory

## 20-Second Demo

```bash
loopback-litmus scan --known-agent-ports
loopback-litmus scan --json > loopback-litmus-report.json
loopback-litmus serve-fixture --case websocket-no-origin
loopback-litmus scan --port 18789
```

Expected report shape:

```text
HIGH  ws://127.0.0.1:18789
      Process: openclaw-like-fixture
      Evidence: cross-origin WebSocket handshake accepted from https://loopback-litmus.invalid
      Why it matters: malicious pages can talk to this local control plane
      Fix: require auth and validate Origin for every WebSocket upgrade
```

## Core v0.1 Feature Set

- Local CLI only. No hosted backend.
- Enumerate local listening TCP services on macOS and Linux.
- Detect loopback versus all-interface binds.
- Identify known AI-agent/MCP/dev-control-plane ports and process names.
- Probe HTTP reachability using safe `GET` and `OPTIONS` requests only.
- Probe WebSocket handshakes with configurable fake Origin headers.
- Probe MCP HTTP endpoints with non-mutating `initialize` and metadata checks only.
- Run a small browser-reachability harness to prove whether browser-origin requests can reach selected ports.
- Include fixture servers for vulnerable and hardened HTTP/WebSocket/MCP patterns.
- Render text and JSON reports.
- Document safety limits, false positives, and exact commands used.

## Non-Goals

- No exploitation payloads.
- No command execution probes.
- No scanning public internet targets.
- No automatic patching.
- No enterprise EDR replacement.
- No prompt-injection, tool-description, or skill-malware scanner.
- No broad generic vulnerability scanner.
- No MCP tool calls beyond safe initialization/listing checks when explicitly enabled.

## Existing Tools And Why This Is Different

- Snyk Agent Scan, Cisco MCP Scanner, and Invariant MCP-Scan scan agent configs, MCP tools, prompt/tool risks, vulnerabilities, and supply-chain issues. `loopback-litmus` focuses on already-running local network surfaces and browser reachability without executing untrusted MCP config commands.
- Microsoft Defender local AI agent discovery and similar enterprise products provide managed endpoint inventory. `loopback-litmus` is a local open-source developer check with reproducible evidence.
- LocalPortScan and browser port scanners identify open ports. `loopback-litmus` adds AI/MCP process correlation, Origin/auth/MCP protocol evidence, and safe remediation guidance.
- MCP Playground security scanner audits a provided MCP URL. `loopback-litmus` discovers local surfaces first and tests the browser-to-loopback threat model.
- OWASP ZAP and WebSocket clients can test WebSockets manually. `loopback-litmus` packages the narrow localhost agent-control-plane checks into a repeatable CLI.

## Why Upstream Contribution Is Insufficient

The incidents span AutoGen Studio, MCP Inspector, Claude Code IDE extensions, Kubectl MCP Server, GPT Researcher, OpenClaw, MCP SDK defaults, and generic browser localhost behavior. Each upstream should fix its own vulnerability, but the recurring developer question is cross-product: what is exposed on this workstation right now, and can browser-origin code reach it?

That cross-product audit is not naturally owned by one upstream project.

## Why This Strengthens Ilia's Profile

This is security-oriented AI SWE infrastructure, not a prompt wrapper. It combines local systems inspection, browser security, WebSocket protocol testing, MCP awareness, safe exploit-class reproduction, fixture-driven tests, and practical developer UX.

## Publish Criteria

- Demand, product, validation, usability, engineering, and distribution gates are recorded as `PASS`, `FAIL`, or `UNKNOWN`.
- At least three unrelated real-world cases are reproduced safely or modeled with faithful public advisory fixtures.
- At least two ecosystems are covered, with Node and Python first.
- Baseline comparison against manual `lsof`/`curl`/generic port-scan workflow is documented.
- No probe can execute commands, mutate local services, or send exploit payloads.
- Tests cover fixture servers, report rendering, port enumeration parsing, and risk classification.
- CI passes on macOS and Linux or clearly documents supported platforms.
- README explains limitations and supported versions accurately.
- Safety review confirms no secrets, no `.env` reads, and no public-target scanning defaults.
