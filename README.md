# CF Worker Trojan 代理节点

基于 Cloudflare Workers 的 Trojan 代理节点，支持三网优选 IP 自动订阅。

## 功能特点

- **Trojan over WebSocket** — 标准 Trojan 协议，兼容主流客户端
- **三网优选 IP** — 通过 Cron 定时任务自动获取电信/联通/移动最优 CF 边缘 IP
- **KV 持久化** — 使用 Workers KV 缓存优选 IP，保证高可用
- **多格式订阅** — 同时支持 Base64 通用、Clash-Meta、Sing-Box 三种订阅格式
- **ProxyIP 支持** — 全局或单节点级别自定义 ProxyIP，解决 CF 套 CF 问题

## 快速部署

### 1. 创建 KV 数据库

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 **Workers & Pages → KV**
3. 点击 **Create a Namespace**，名称输入 `CF_IP_KV`

### 2. 创建 Worker

1. 进入 **Workers & Pages → Create Application → Create Worker**
2. 命名为 `cf-trojan-proxy`，点击 **Deploy**
3. 点击 **Edit code**，将 `_worker.js` 内容粘贴到编辑器中
4. 进入 **Settings → Variables**：
   - **KV Namespace Bindings**：Variable name 填 `CF_IP_KV`，选择刚创建的 KV
   - **Environment Variables**（可选）：
     - `pswd` = 你的 Trojan 密码（默认：`trojan`）
     - `proxyip` = ProxyIP 地址（可选）
5. 点击 **Save and deploy**

### 3. 配置 Cron（自动优选 IP）

1. 进入 Worker 的 **Settings → Triggers**
2. 点击 **Add Cron Trigger**
3. Cron Schedule 输入 `0 */4 * * *`（每 4 小时执行一次）
4. 点击初始 **Test** 按钮手动触发一次，确保 KV 写入初始数据

### 4. 使用 wrangler 部署（替代方案）

```bash
# 安装 wrangler
npm install -g wrangler

# 登录
wrangler login

# 创建 KV
wrangler kv:namespace create CF_IP_KV

# 将返回的 ID 填入 wrangler.toml 后部署
wrangler deploy
```

## 订阅链接

部署完成后，在客户端中添加以下订阅链接：

| 格式 | 链接 |
|------|------|
| 通用 Base64 | `https://你的域名/sub` |
| Clash-Meta | `https://你的域名/clash` |
| Sing-Box | `https://你的域名/singbox` |

## 自定义 ProxyIP

支持两种方式设置 ProxyIP：

1. **全局变量**：在 Worker 环境变量中设置 `proxyip`
2. **单节点路径**：在客户端路径中使用 `/pyip=IP地址:端口`

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `pswd` | Trojan 密码 | `trojan` |
| `proxyip` | ProxyIP 地址 | 无 |

## 推荐客户端

- **Android**: v2rayNG、Nekobox、Karing
- **Windows**: v2rayN、Hiddify、Karing
- **iOS**: Karing、Shadowrocket、Streisand
- **路由器**: passwall、ssr-plus、homeproxy

## 致谢

- [yonggekkk/Cloudflare-vless-trojan](https://github.com/yonggekkk/Cloudflare-vless-trojan) — Trojan 协议实现参考
- [emn178/js-sha256](https://github.com/emn178/js-sha256) — SHA-224/256 哈希库
- [cf.090227.xyz](https://cf.090227.xyz) — 三网优选 IP API