---
title: "Getting Started"
description: "Install and configure Ephyr"
weight: 30
---

## Requirements

- **Go 1.24+** -- uses enhanced routing patterns and recent stdlib features
- **Linux** -- `SO_PEERCRED` for Unix socket peer authentication is Linux-specific
- **systemd** -- optional but recommended for production
- **OpenSSH** -- target hosts need `TrustedUserCAKeys` configured
- **nftables** -- recommended for network isolation

## Quick Start with Docker

```bash
git clone https://github.com/EphyrAI/Ephyr.git
cd Ephyr
./examples/generate-ca-key.sh
docker compose up --build -d
```

Dashboard at `http://localhost:8553` (token: `changeme`). Edit `examples/policy.yaml` to add your targets.

## Build from Source

```bash
git clone https://github.com/EphyrAI/Ephyr.git
cd Ephyr
make build
# Output: bin/ephyr-broker  bin/ephyr-signer  bin/ephyr
```

## One-Command Setup

```bash
sudo make setup
# Builds, installs, creates user, generates CA key, writes example policy,
# installs systemd units, and starts services.
```

Customize with: `sudo make setup DASHBOARD_TOKEN=mysecret MCP_PORT=9000 DASHBOARD_PORT=9001`

## Generate CA Key

```bash
mkdir -p /etc/ephyr
ssh-keygen -t ed25519 -f /etc/ephyr/ca_key -N ""
```

Deploy the public key (`/etc/ephyr/ca_key.pub`) to your target hosts:

```bash
# On each target host, add to /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/ephyr_ca.pub
```

## Configure Policy

Create `/etc/ephyr/policy.yaml`:

```yaml
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"

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

## Install and Start

```bash
sudo make install-user
sudo make install-systemd
sudo systemctl enable --now ephyr-signer
sudo systemctl enable --now ephyr-broker
```

Always start the signer before the broker. Both share `/run/ephyr/`.

## Connect an Agent

### Claude Code / Claude Desktop

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "ephyr": {
      "type": "url",
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

Works with Claude Code, Claude Desktop, Cursor, Cline, OpenClaw, and any MCP-compatible client.

### CLI

```bash
ephyr targets                  # List available SSH targets
ephyr exec webserver \
  --role read \
  -- systemctl status nginx    # Run a command

ephyr session create           # Open persistent session (60x faster)
ephyr services                 # List HTTP proxy services
ephyr remotes                  # List federated MCP servers
ephyr inspect <token>          # Inspect macaroon caveats
ephyr monitor                  # Live broker activity monitoring
ephyr demo                     # Demonstration mode
ephyr host-key                 # SSH host key management
```

## Testing

253+ tests across 13+ test files:

```bash
make test                      # Unit tests
make lint                      # golangci-lint
go test ./test/integration/    # Integration tests (requires running instance)
```

## What's Next

- [How It Works](/docs/how-it-works/) -- understand the access model
- [Architecture](/docs/architecture/) -- security model and process isolation
- [Whitepapers](/whitepapers/architecture/) -- full architecture specification
- [GitHub](https://github.com/EphyrAI/Ephyr) -- source code, issues, and documentation
