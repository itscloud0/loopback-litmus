# Benchmark Results

Status: `PASS` for the fixture/manual workflow benchmark.

Run recorded: 2026-06-23 12:10 CEST.

## Scope

The benchmark starts safe local fixtures plus ordinary local HTTP samples. It does not run historical vulnerable products, execute MCP configs, call tools, spawn commands through services, use credentials, or touch a Kubernetes cluster.

## Reproducible Command

```bash
PYTHONPATH=src python3 scripts/benchmark.py --output BENCHMARK_RESULTS.md
```

## Results

| Scenario | Group | Expected | Actual | Result |
| --- | --- | --- | --- | --- |
| `advisory-mcp-inspector-open` | `unsafe` | `HIGH` | `HIGH` | `PASS` |
| `advisory-claude-ide-ws-open` | `unsafe` | `HIGH` | `HIGH` | `PASS` |
| `advisory-kubectl-mcp-open` | `unsafe` | `HIGH` | `HIGH` | `PASS` |
| `advisory-gpt-researcher-ws-open` | `unsafe` | `HIGH` | `HIGH` | `PASS` |
| `websocket-origin-enforced` | `hardened` | `LOW` | `LOW` | `PASS` |
| `mcp-auth-required` | `hardened` | `LOW` | `LOW` | `PASS` |
| `plain-http-dev-page` | `ordinary` | `INFO` | `INFO` | `PASS` |
| `plain-json-health-api` | `ordinary` | `INFO` | `INFO` | `PASS` |
| `plain-404-router` | `ordinary` | `INFO` | `INFO` | `PASS` |

## Metrics

- Unsafe fixture true positives: `4/4`.
- Hardened control true negatives: `2/2`.
- Ordinary dev-server false positives: `0/3` for `HIGH` or `MEDIUM` risk.
- `loopback-litmus scan` elapsed time: `0.097` seconds.
- Manual-equivalent baseline elapsed time: `0.055` seconds.
- `loopback-litmus scan` command count: `1`.
- Manual-equivalent command count: `28`.
- Manual commands replaced: `27`.

## Manual Baseline

The baseline models the documented manual workflow as one listener-discovery command plus three checks per port: `curl`-style HTTP GET, hostile-Origin WebSocket handshake, and MCP `initialize` POST.

Manual baseline command shapes:
- `lsof -iTCP -sTCP:LISTEN -n -P or ss -H -ltnp`
- `curl-style GET / per port`
- `WebSocket hostile-Origin handshake per port`
- `MCP initialize POST per port`

## False-Positive Sampling

The ordinary local samples were a plain HTML dev page, a plain JSON health API, and a 404 router. None were classified `HIGH` or `MEDIUM`.

## Failures And Limits

- No fixture classification failures observed.
- Timings are local workstation measurements and should be treated as workflow-order evidence, not a universal performance claim.
- Process attribution was not benchmarked because fixed-port fixture targets bypass listener enumeration.
- Browser-engine behavior for Private Network Access and `0.0.0.0` remains future browser-harness work.

## Gate Status

- Benchmark: `PASS`, citing this benchmark run and the scenarios above.
- Discoverability: `PASS`, citing `DISCOVERABILITY.md`, `RELEASE_NOTES.md`, `README.md`, and `pyproject.toml`.
- Publication: `READY_FOR_PRIVATE_PUBLISH`; public release remains blocked by the public-repo cooldown until 2026-06-25 19:56 Europe/Amsterdam.
