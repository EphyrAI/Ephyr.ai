---
title: "How It Works"
description: "How Ephyr provides ephemeral infrastructure access for AI agents"
weight: 10
---

## The Short Version

Ephyr is a broker. It sits between AI agents and your infrastructure. Agents connect to one MCP endpoint. Ephyr handles credentials, policy, and proxying on their behalf.

No SSH keys scattered across hosts. No API tokens in agent runtimes. No standing access.

A single MCP connection replaces N different authentication mechanisms with one unified, policy-governed interface. Every action is scoped, time-limited, and logged.

## Three Access Paths

### SSH via Ephemeral Certificates

When an agent needs to run a command on a remote host, Ephyr requests a short-lived SSH certificate from the isolated signer process. The certificate is scoped to a specific principal (role) and defaults to a 5-minute TTL. The agent never sees or holds an SSH key.

For sequential commands, persistent sessions reduce latency from ~850ms to ~14ms per command.

### HTTP Proxy with Credential Injection

Agents make HTTP requests through Ephyr's proxy. The broker injects the appropriate credentials (bearer tokens, basic auth, custom headers) based on the target service. The agent references services by name, never by credential.

### MCP Federation

Ephyr aggregates tools from remote MCP servers. Agents see a unified tool catalog. The broker handles discovery, health checking, and transparent proxying.

## Task-Scoped Identity

Every action in Ephyr correlates to a task identified by a ULID. Tasks have capability envelopes that define what they can access. When a task is revoked, all its grants are instantly invalidated via epoch watermarking — no revocation lists, no propagation delay.

## Delegation

Parent tasks can delegate to child tasks with attenuated scope. Macaroon-based tokens use HMAC-chained caveats to make restriction removal cryptographically impossible. The effective capability of a child task is always the intersection of the parent's envelope and the child's policy — capabilities only shrink, never grow.

This implements the Delegation Capability Token architecture from DeepMind's "Intelligent AI Delegation" framework (arXiv:2602.11865).

## Policy

Access control is defined in a YAML policy file:

```yaml
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 3
    can_delegate: true

roles:
  read:
    principal: "agent-read"
  operator:
    principal: "agent-op"

targets:
  webserver:
    host: "10.0.1.10"
    port: 22
    allowed_roles: [read, operator]
    auto_approve: true
```

Policy reloads on SIGHUP. No restart required.

## Audit

Every certificate issuance, command execution, HTTP proxy request, delegation, and denial is logged as structured JSON with full task lineage correlation. "What happened during this deployment?" is a single query.
