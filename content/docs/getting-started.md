---
title: "Getting Started"
description: "Install and configure Ephyr"
weight: 30
---

## Requirements

- Go 1.24+
- Linux with systemd
- SSH server on target hosts configured to trust the Ephyr CA

## Build

```bash
git clone https://github.com/ben-spanswick/Clauth.git
cd Clauth
make build
# Output: bin/ephyr-broker  bin/ephyr-signer  bin/ephyr
```

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

### CLI

```bash
ephyr targets              # List available SSH targets
ephyr exec webserver \
  --role read \
  -- systemctl status nginx  # Run a command

ephyr session create       # Open persistent session (faster)
ephyr services             # List HTTP proxy services
ephyr remotes              # List federated MCP servers
```

## What's Next

- [How It Works](/docs/how-it-works/) — understand the access model
- [Architecture](/docs/architecture/) — security model and process isolation
- [GitHub](https://github.com/ben-spanswick/Clauth) — source code and issues
