# Ingress & Domain Binding Guide

This guide describes how to bind your custom private or public domain to **Server Agents Gateway** while keeping zero open inbound ports on your host firewall.

---

## Architecture Overview

```
[Remote AI Agents (Mobile / Cursor / Claude Code)]
                     │
                     ▼ (HTTPS: gateway.yourdomain.com)
┌────────────────────────────────────────────────────────┐
│     Cloudflare Edge / Zero Trust Network               │
│     - Automatic SSL/TLS termination                   │
│     - Optional Cloudflare Service Token validation     │
│     - DDoS mitigation and IP masking                   │
└────────────────────┬───────────────────────────────────┘
                     │ (Encrypted QUIC / HTTP2 Tunnel)
                     ▼
┌────────────────────────────────────────────────────────┐
│     Host Server (No Public Inbound Ports Open)         │
│     - cloudflared daemon                               │
│     - Routes traffic to: 127.0.0.1:4180                │
└────────────────────┬───────────────────────────────────┘
                     ▼
┌────────────────────────────────────────────────────────┐
│     Server Agents Gateway (server.py)                  │
│     - Evaluates Per-Agent Bearer Tokens                │
│     - Enforces Fencing Locks & Safety Sandboxes        │
└────────────────────────────────────────────────────────┘
```

---

## Method 1: Cloudflare Tunnel (Zero Open Inbound Ports · Recommended)

Cloudflare Tunnel (`cloudflared`) connects your local loopback service directly to Cloudflare's global edge without opening any inbound ports on your firewall (e.g. UFW/iptables).

### Option A: Cloudflare Zero Trust Web Dashboard (Zero CLI Config)
1. Go to **Cloudflare Zero Trust Dashboard** → **Networks** → **Tunnels**.
2. Select your active tunnel and click **Configure**.
3. Under the **Public Hostname** tab, click **Add a public hostname**:
   - **Subdomain**: `gateway` (or your preferred subdomain)
   - **Domain**: `yourdomain.com`
   - **Type**: `HTTP`
   - **URL**: `127.0.0.1:4180`
4. Click **Save hostname**. Cloudflare will automatically route `https://gateway.yourdomain.com` to your local gateway service.

---

### Option B: Cloudflare Tunnel Local Configuration File (`config.yml`)
If you manage your tunnel via local YAML configuration, add an ingress entry in `/etc/cloudflared/config.yml`:

```yaml
tunnel: <YOUR-TUNNEL-UUID>
credentials-file: /etc/cloudflared/<YOUR-TUNNEL-UUID>.json

ingress:
  # Route your gateway domain to loopback 4180
  - hostname: gateway.yourdomain.com
    service: http://127.0.0.1:4180
    originRequest:
      connectTimeout: 10s
      noTLSVerify: false

  # Catch-all rule (mandatory for cloudflared)
  - service: http_status:404
```

Restart the tunnel service to apply changes:
```bash
sudo systemctl restart cloudflared
```

---

## Method 2: Caddy / Nginx Reverse Proxy (Self-Hosted Edge)

If you terminate SSL locally via Caddy or Nginx:

### Caddy (`Caddyfile`)
```caddy
gateway.yourdomain.com {
    reverse_proxy 127.0.0.1:4180 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
    }
}
```

### Nginx (`nginx.conf`)
```nginx
server {
    listen 443 ssl http2;
    server_name gateway.yourdomain.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE and streaming support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}
```

---

## Extra Security: Machine-to-Machine (M2M) Service Tokens

To prevent unauthorized public probing or crawlers from even reaching your gateway endpoint, configure **Cloudflare Access Service Auth**:
1. In Cloudflare Zero Trust: **Access** → **Service Tokens** → **Create Service Token** (e.g. `gateway-agent-token`).
2. Note the generated `Client ID` and `Client Secret`.
3. In **Access** → **Applications**, create an application for `gateway.yourdomain.com`:
   - Add an Access Policy: `Action: Service Auth`
   - Criteria: `Include` → `Service Token` → select `gateway-agent-token`.
4. Configure connecting AI agents to include these headers with every request:
   ```http
   CF-Access-Client-Id: <YOUR-CLIENT-ID>
   CF-Access-Client-Secret: <YOUR-CLIENT-SECRET>
   Authorization: Bearer <YOUR-AGENT-BEARER-TOKEN>
   ```
Requests lacking valid Service Token headers will be dropped immediately at Cloudflare's edge with `403 Forbidden`.