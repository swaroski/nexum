---
title: Integrations
description: What Nexum works with today, and what's planned. Nothing is listed as supported until it exists.
---

Nexum is neutral by design: the security core sees identities, delegated
authority, actions and resources, never a framework, model or cloud.

**Status:** **Alpha** = shape settling · **Experimental** = may change ·
**Planned** = on the [roadmap](/nexum/project/roadmap/), not built.

## Protocols

| | Status | |
|---|---|---|
| REST decision API | Alpha | [HTTP API](/nexum/reference/http-api/) |
| MCP (Streamable HTTP) | Experimental | [guide](/nexum/guides/mcp/) |
| A2A v1.0 JSON-RPC | Experimental | [guide](/nexum/guides/a2a/) |
| HTTP reverse proxy, Envoy `ext_authz`, gRPC | Planned | |

## Agent frameworks

Any framework works through the decision API or the MCP/A2A proxies.

| | Status | |
|---|---|---|
| Python (any framework) | Experimental | [client](/nexum/guides/python/) |
| LangGraph | Experimental | [example](https://github.com/swaroski/nexum/tree/main/examples/langgraph) |
| CrewAI, Mastra, OpenAI Agents SDK, Semantic Kernel, Google ADK | Planned | |
| TypeScript, Go clients | Planned | |

## Identity

| | Status |
|---|---|
| SPIFFE IDs for agents | Alpha |
| SPIRE SVIDs, OIDC, Entra ID, Okta, AWS/GCP workload identity, RFC 8693 token exchange | Planned |

## Policy engines

| | Status |
|---|---|
| Built-in engine | Alpha |
| OPA | Experimental · [guide](/nexum/guides/opa/) |
| Cedar, Cerbos, SpiceDB | Planned |

## Discovery and management

| | Status | |
|---|---|---|
| A2A Agent Card discovery (passive) | Experimental | [guide](/nexum/guides/discovery-risk/) |
| Local console | Experimental | [guide](/nexum/guides/console/) |
| Kubernetes, MCP server discovery | Planned | |
| Hosted console | Planned (after demand) | |

## Observability

| | Status | |
|---|---|---|
| OpenTelemetry traces (OTLP/HTTP) | Experimental | [guide](/nexum/guides/observability/) |
| Prometheus metrics | Experimental | |
| JSON logs (Splunk, Elastic, CloudWatch, Loki, …) | Experimental | |
| SIEM audit export | Planned | |

## CI/CD

| | Status | |
|---|---|---|
| GitHub Actions (security evals) | Experimental | [guide](/nexum/guides/evals/#in-ci) |
| GitLab, Azure DevOps | Planned | |

## Deployment

| | Status | |
|---|---|---|
| Local process, Docker, Kubernetes | Alpha | [deploy](/nexum/guides/deploy/) |
| Helm, cloud marketplace images | Planned | |
