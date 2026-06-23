# Demand Evidence

Current status: `PASS` for research gate, standalone gap, product spec, build, validation, benchmark, and discoverability. Adoption remains `UNKNOWN` because the project is not public yet.

## Target User

Developers and security engineers running local AI agent tooling, MCP servers, IDE helpers, browser automation, or dev control planes on workstations.

## Painful Workflow

The user needs to know whether a malicious website or browser-equipped agent can reach a local control plane. Today that requires manual process inspection, port guessing, browser/WebSocket testing, protocol knowledge, and product-specific CVE reading.

## Public Pain Signals

| Signal | Source | Evidence | Gate |
| --- | --- | --- | --- |
| Browser agent to local MCP RCE | https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/ | Microsoft AutoJack shows untrusted web content rendered by a browsing agent reaching a local MCP WebSocket and spawning processes on the host. | `PASS` |
| MCP Inspector drive-by RCE | https://www.tenable.com/blog/how-tenable-research-discovered-a-critical-remote-code-execution-vulnerability-on-anthropic | Tenable reports CVE-2025-49596, where a workstation could be compromised by visiting a malicious website while MCP Inspector was exposed. | `PASS` |
| Claude Code IDE extension localhost WebSocket issue | https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/ | Datadog describes malicious websites connecting to unauthenticated local WebSocket servers in Claude Code IDE extensions. | `PASS` |
| Kubernetes control through local MCP | https://www.ox.security/blog/cve-2025-65719-critical-rce-in-kubectl-mcp-server/ | OX reports a malicious website could connect to localhost and exploit Kubectl MCP Server, exposing the local system and Kubernetes clusters. | `PASS` |
| GPT Researcher unauthenticated WebSocket RCE | https://github.com/assafelovic/gpt-researcher/issues/1694 | Public issue reports unauthenticated RCE through `/ws` by sending MCP config command/args that reached process spawning. | `PASS` |
| Public and internal exposed MCP servers | https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities | Bitsight found roughly 1,000 exposed MCP servers without authorization and warns internal instances can still be exploitable. | `PASS` |
| OpenClaw local WebSocket takeover | https://labs.cloudsecurityalliance.org/research/csa-research-note-clawjacked-websocket-local-agent-hijack-20/ | CSA documents ClawJacked, where malicious websites could seize control of a locally running OpenClaw instance through WebSocket trust failures. | `PASS` |
| Generic browser-to-localhost risk | https://www.oligo.security/blog/0-0-0-0-day-exploiting-localhost-apis-from-the-browser | Oligo shows public websites can interact with localhost services through browser behavior and 0.0.0.0 handling on affected systems. | `PASS` |

## Current Workarounds

- Patch individual products after advisories.
- Stop local agents, MCP inspectors, and IDE helper services when browsing.
- Use isolated VMs, containers, devcontainers, or dedicated browser profiles.
- Manually run `lsof`, `netstat`, `ss`, `curl`, nmap, WebSocket clients, browser DevTools, or OWASP ZAP.
- Use enterprise inventory and runtime protection where available.
- Use general MCP security scanners for config/tool analysis.

## Existing Tools Reviewed

| Tool | Source | Coverage | Gap for this project |
| --- | --- | --- | --- |
| Snyk Agent Scan | https://github.com/snyk/agent-scan | Discovers agent configs, MCP servers, and skills; scans prompt/tool/security risks. | It may execute configured MCP commands to inspect tools and is not focused on safe live loopback browser-reachability evidence. |
| Cisco MCP Scanner | https://github.com/cisco-ai-defense/mcp-scanner | Scans MCP servers/tools with YARA, LLM judging, Cisco AI Defense, dependency checks, and readiness checks. | Broader MCP content/security scanner, not a narrow local browser-to-loopback litmus. |
| Invariant MCP-Scan | https://invariantlabs.ai/blog/introducing-mcp-scan | Scans MCP risks such as tool poisoning and rug pulls. | Focuses on MCP semantics, not running local ports and browser-origin reachability. |
| Microsoft Defender local AI agent discovery | https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview | Enterprise discovery of supported local agents and MCP configs. | Managed platform, not open local developer CLI with reproducible probes. |
| LocalPortScan | https://localportscan.com/ | Browser-based scan of localhost ports. | Finds open ports but not AI/MCP classification, WebSocket Origin/auth behavior, process correlation, or MCP handshake risk. |
| MCP Playground Security Scanner | https://mcpplaygroundonline.com/mcp-security-scanner | URL-based MCP audit with transport, auth, protocol, CORS, and security checks. | Requires a known URL and does not solve local discovery plus browser-to-localhost threat modeling. |
| OWASP WebSocket testing guidance | https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets | Explains Origin, auth, authorization, and WebSocket testing. | Manual methodology, not an agent/MCP workstation audit tool. |

## Clear Standalone Gap

`PASS`: a local, safe, reproducible browser-to-loopback audit for already-running AI agent and MCP control planes.

The important distinction is "prove reachability from a browser-origin threat model without executing untrusted MCP configs or exploit payloads." Existing tools either scan configs/tools, provide enterprise inventory, scan public URLs, or perform generic port discovery.

## Why Upstream Contribution Is Insufficient

`PASS`: the vulnerability class spans multiple vendors, SDKs, local agents, MCP servers, IDE extensions, browser behaviors, and developer workflows. Upstream fixes remain necessary, but no single upstream owns local workstation cross-product exposure inventory.

## Credible Distribution Path

`PASS`:

- MCP and AI security communities are actively discussing scanners and local-agent risk.
- Security researchers are publishing repeated advisories in the exact threat class.
- The initial CLI can be distributed through GitHub, PyPI/uvx, Homebrew later, and posts targeting MCP/server authors.
- Good launch artifact: scan your workstation before and after patching a known fixture.

## Measurable Success Criteria

- Detect at least three safe fixture classes: unauthenticated HTTP metadata, WebSocket without Origin enforcement, and MCP initialize without auth.
- Correctly classify bind address risk for loopback versus all-interface services.
- Produce the same high-risk verdicts on advisory-faithful fixtures modeled after MCP Inspector, OpenClaw, and Kubectl MCP patterns.
- Reduce manual audit time versus `lsof` plus ad hoc `curl`/WebSocket testing.
- Avoid false claims of exploitability when a service requires auth or rejects hostile Origin headers.

## Kill Criteria

- Kill if Snyk Agent Scan, Cisco MCP Scanner, Defender, LocalPortScan, or MCP Playground adds the same local browser-reachability workflow before implementation.
- Kill if useful checks require exploit payloads or command execution.
- Kill if safe probes cannot distinguish normal developer servers from agent control planes with acceptable precision.
- Kill if validation cannot cover at least three unrelated real-world cases or faithful public-advisory fixtures.
- Kill if the result collapses into a tiny port checker.
