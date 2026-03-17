---
title: "How It Works"
description: "How Ephyr provides cryptographically bounded agent authority"
weight: 10
---

## Overview

Ephyr is an access broker. It sits between AI agents and infrastructure, replacing scattered credentials with a single MCP endpoint that enforces policy, issues ephemeral certificates, and produces structured audit logs. Every action is scoped to a task, time-bounded, and cryptographically traceable through the delegation chain.

## Three-Process Architecture

Ephyr runs as three isolated processes with strict privilege separation.

**ephyr signer** holds the Ed25519 CA private key in a systemd sandbox with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and zero capabilities. Unix socket IPC only. The CA key never leaves this process, never touches the network.

**ephyr broker** handles everything else: HMAC chain verification, caveat reduction, policy evaluation, SSH certificate requests via signer IPC, HTTP proxy with credential injection, MCP federation, task tree management, structured audit logging, and the admin dashboard.

**ephyr** is a single binary with all subcommands: `ephyr broker` and `ephyr signer` start the servers, `ephyr init` runs the setup wizard, and agent-side commands include `ephyr inspect` (examine macaroon caveats), `ephyr monitor` (live broker activity), `ephyr status` (health check with optional `--restart`), `ephyr demo` (demonstration mode), `ephyr host-key` (SSH host key management), and `ephyr version`.

The signer issues delegation certificates to the broker. The broker signs task tokens locally with its delegation key -- no IPC round-trip per token. Delegation keys auto-rotate before expiry.

## Three Access Paths

### SSH via Ephemeral Certificates

Ed25519 certificates with 5-minute default TTL, configurable up to 30 minutes per-target. Each certificate is scoped to agent, target, and role. Duplicate certificates for the same agent+target+role are automatically revoked.

Persistent sessions reduce per-command latency from ~850ms to ~14ms (60x speedup).

### HTTP Proxy with Credential Injection

Configure a service once with its URL prefix and credentials. Agents make requests by name -- they never see the token. Supports bearer, basic auth, custom header, and query parameter injection. CIDR allow/deny policy controls reachable destinations.

### MCP Federation

Aggregate tools from remote MCP servers through a unified endpoint. Automatic discovery via MCP handshake. Tools namespaced as `{server}.{tool}` (e.g., `devtools.list_repos`). Background refresh keeps catalogs current.

## Macaroon-Based Task Identity

Agents create tasks via `task_create` and receive a macaroon-based token (prefixed `mac_`). The token carries a ULID task ID, a capability envelope, and an HMAC caveat chain.

**HMAC-chained caveats** make restriction removal cryptographically impossible. The broker's effective envelope reducer derives the most-restrictive authority using set intersection, minimums, and boolean AND. The HMAC chain proves caveat accumulation; the reducer derives semantic narrowing. These are distinct guarantees.

**Dual-mode authentication:** The broker accepts macaroon tokens (`mac_`), legacy JWT tokens (`eyJ`), and API keys. Existing auth continues to work.

## Delegation with Attenuation

Parent tasks delegate to children with attenuated scope. The broker mediates every delegation for audit and pre-validation. Children receive macaroons with additional caveats that further restrict the envelope.

- Cross-agent delegation: `claude` can delegate to `investigator-bot`
- Child gets the intersection of parent ceiling and child policy
- Maximum chain depth: 5
- Child TTL cannot exceed parent's remaining TTL
- No offline delegation -- the broker is always in the loop

## Epoch Watermark Revocation

`task_revoke` invalidates all tokens for a task by setting an epoch timestamp. Validation checks the watermark in O(depth) with no per-token blocklists. Cascading revocation propagates to all child tasks. Watermarks self-clean when max TTL passes.

## Policy Engine

Declarative YAML with hot-reload via SIGHUP. Eight-step evaluation pipeline: agent exists, target exists, role allowed, duration clamped, concurrent limits, duplicate handling, global limits, approval mode. Every denial includes a specific reason.

## RBAC

Fine-grained per-agent access control across all three proxy paths and the dashboard:

| Layer | What it checks |
|-------|----------------|
| SSH exec | Agent's roles for the target, intersection with target's `allowed_roles` |
| HTTP proxy | Agent's allowed services and permitted HTTP methods |
| MCP federation | Agent's allowed remotes and optional tool restrictions |
| Discovery | Filters `list_targets`, `list_services`, `list_remotes` results |
| Dashboard | Agent's dashboard access level (none/viewer/operator/admin) |

Template inheritance, wildcard support, and agent-level overrides. Discovery tools automatically filter to show only what the agent can access.

## Resource URIs

Seven resource URIs enable agent self-discovery without tool calls:

| URI | Contents |
|-----|----------|
| `ephyr://overview` | System summary with all targets, services, permissions |
| `ephyr://targets` | SSH targets with roles, TTLs, auto-approve settings |
| `ephyr://services` | Proxy services with auth types and URL prefixes |
| `ephyr://roles` | Role definitions and SSH principal mappings |
| `ephyr://status` | Active certificates, sessions, recent activity |
| `ephyr://tools` | Tool reference with parameters and usage examples |
| `ephyr://remotes` | Federated MCP servers with tools and status |

## Holder Binding (Ephyr Bind)

Task tokens are bearer by default. Ephyr Bind (v0.3) adds opt-in holder binding: tasks created with `holder_pub_key` or bound via `task_bind` require proof-of-possession (Ed25519 signature over nonce, timestamp, body hash, and macaroon digest) on every request. PoP verification is enforced in the broker auth hot path. Leaked macaroons are useless without the corresponding private key. No mTLS infrastructure required. Full PoP pipeline completes in ~132us.

## Command and Request Filtering

Opt-in defense-in-depth filtering across all three proxy paths:

- **SSH command filtering** -- deny/allow patterns checked before the SSH connection is established. No certificate is issued for blocked commands.
- **HTTP proxy filtering** -- URL path and request body patterns checked before the request is sent.
- **MCP federation filtering** -- serialized tool arguments checked against deny patterns before forwarding.
- **Auto-revoke** -- optionally suspend agent access on violation, requiring human re-enablement from the dashboard.

Zero overhead when disabled (~3.9ns). Not a security boundary -- commands can be obfuscated. The real enforcement is host-level controls. Filtering catches the obvious cases and provides an audit trail.

## Proxy Hardening

The HTTP proxy applies defense-in-depth hardening to all outbound requests:

- **Hop-by-hop header stripping** -- removes `Connection`, `Proxy-Authorization`, `TE`, and other hop-by-hop headers that should not transit proxies.
- **httpoxy mitigation** -- strips the `Proxy` header from inbound requests to prevent CGI/WSGI `HTTP_PROXY` environment variable injection (CVE-2016-5385 and related).
- **Redirect blocking** -- the proxy does not follow redirects. Open redirect chains cannot be used to exfiltrate injected credentials to attacker-controlled endpoints.

These mitigations are always active and cannot be disabled.

## Audit

Every certificate, command, HTTP proxy request, delegation, and denied action is logged as structured JSON with ULID task correlation. "What happened during this deployment?" is a single query. Real-time event streaming via WebSocket.

## Observability

Prometheus metrics endpoint (`GET /v1/metrics`) with 8 latency histograms and 13 counters/gauges covering tasks, tokens, delegation, auth cache, macaroon operations, and legacy requests.
