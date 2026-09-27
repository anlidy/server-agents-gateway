# claude.ai 连接器（网页 / 桌面 / 手机 App）

claude.ai 的「自定义连接器」就是一个远程 MCP 服务器，但它只支持 OAuth：不能手填 `Authorization` 头，也过不了 Cloudflare Access 的 Service Token。所以网关自带一个最小的 OAuth 2.1 授权服务（`sag/oauth.py`），和静态 token 走同一个域名；Cloudflare 上只给 Anthropic 的出口和授权页开 Access 旁路。在网页上添加一次，桌面版和手机 App 会自动同步。

## 怎么做到的

- **发现**：`/mcp` 没有有效令牌时回 401，带 `WWW-Authenticate: Bearer resource_metadata=…`；`/.well-known/oauth-protected-resource`、`/.well-known/oauth-authorization-server` 给出元数据。
- **注册**：动态注册（RFC 7591），只收公开客户端，回调地址必须在 `GATEWAY_OAUTH_REDIRECT_URIS` 里（默认 claude.ai / claude.com 的回调，加上本机回环地址）。
- **授权页**：不做账号登录。root 在服务器上跑 `python3 -m sag oauth-pair <agent_id>` 得到一次性配对码（10 分钟有效），在授权页上填。配对码决定这次授权以哪个 agent 身份接入。
- **令牌**：PKCE S256 必须；访问令牌 `sago_…` 1 小时，刷新令牌 `sagr_…` 30 天，每次刷新都换新的（旧的作废）。库里只存哈希。
- **身份**：OAuth 接入的 agent 一律是 operator，不能给 root admin 配对。审计、回收站、未读提示、消息和任务都和静态 token 一样，审计里的 `agent_id` 就是配对时写的那个。授权成功本身也记一条审计（`tool_name=oauth_authorize`）。
- **同一个域名**：静态 `sag_` token 和 OAuth 令牌都收。（可选 `GATEWAY_OAUTH_ONLY_HOSTS`：列出的域名只收 OAuth 令牌，给「另开一个无 Access 域名」的部署用。）
- **吊销**：`hub_revoke_agent_token` 吊销 agent 时连带吊销它的 OAuth 令牌（重新签发也不会复活）；只断 OAuth、保留静态 token 用 `oauth-revoke`。

## 服务器上的设置

`.env`：

```
GATEWAY_PUBLIC_URL=https://gateway.example.com
# 以下都有默认值，一般不用写
# GATEWAY_OAUTH_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,loopback
# GATEWAY_OAUTH_ONLY_HOSTS=
# GATEWAY_OAUTH_ACCESS_TTL_MINUTES=60
# GATEWAY_OAUTH_REFRESH_TTL_DAYS=30
# GATEWAY_OAUTH_PAIRING_TTL_MINUTES=10
```

改完重启网关。

## Cloudflare Access 旁路

claude.ai 的请求分两路：发现、注册、换令牌、MCP 调用都从 Anthropic 的服务器发出（出口 `160.79.104.0/21`）；授权页 `/oauth/authorize` 是在你自己的浏览器里打开的。所以 Access 上开两个口子，其余请求照旧要 Service Token：

1. Zero Trust → Access → Applications → gateway 这个应用 → Policies → 添加策略：Action **Bypass**，Include → **IP ranges** → `160.79.104.0/21`。
2. 再建一个 Self-hosted 应用，域名填 `gateway.example.com`，路径填 `oauth/authorize`，策略 Action **Bypass**，Include → **Everyone**。（比整个域名更具体的路径应用优先生效。授权页本身要配对码，公开也没关系。）

Anthropic 如果换了出口 IP 段，连接器会连不上，到时更新第 1 步的 IP 段即可（以 Anthropic 文档公布的为准）。

另一种做法和 xiaoyao-memory 一样：直接去掉这个域名的 Access，全靠网关的 token。更省事，但少了一层：静态 token 一旦泄露就是 root。

如果 Cloudflare 的 WAF / Bot Fight / 浏览器完整性检查拦了 Anthropic 的请求（claude.ai 报 "Couldn't reach the MCP server"），也给 `160.79.104.0/21` 加跳过规则。

## 在 claude.ai 上添加

1. 服务器上用 root 生成配对码：`python3 -m sag oauth-pair claude:web`（agent 不存在会自动以 operator 建出来）
2. claude.ai →「设置 → 连接器」→「添加自定义连接器」
   - 名称：`xiaoyaohub`
   - URL：`https://gateway.example.com/mcp`
   - OAuth 客户端 ID / 密钥：留空（Claude 会自动注册）
3. 点「连接」，浏览器会打开授权页，输入配对码，点「授权」。
4. 在对话里打开这个连接器，让 Claude 调一下 `hub_get_status` 试试。

## 管理

```bash
python3 -m sag oauth-pair <agent_id> [有效分钟数]   # 生成一次性配对码
python3 -m sag oauth-list                          # 列出有效的授权（不含令牌）
python3 -m sag oauth-revoke <agent_id>             # 吊销它名下所有 OAuth 授权，静态 token 不动
```

在 claude.ai 里断开连接器只是客户端不再用了，服务端的刷新令牌要到 30 天后才自然失效；想立刻断，用 `oauth-revoke`。

**提醒**：这个连接器给的是服务器 root shell。授权页只在你自己刚点了「连接」时填配对码；配对码不要发给别人。
