# CF Worker Trojan 代理节点

基于 Cloudflare Workers 的 Trojan 代理节点，使用优选域名自动订阅。

## 功能特点

- **Trojan over WebSocket** — 标准 Trojan 协议，兼容主流客户端
- **优选域名** — 使用 `ygking.cf.090227.xyz` 自动选择最优 CF 边缘节点
- **多格式订阅** — 同时支持 Base64 通用、Clash-Meta、Sing-Box 三种订阅格式
- **ProxyIP 支持** — 全局或单节点级别自定义 ProxyIP

## 快速部署

### 方式一：CF Dashboard

1. 进入 **Workers & Pages → Create Application → Create Worker**
2. 命名为 `cf-worker-point`，点击 **Deploy**
3. 点击 **Edit code**，将 `_worker.js` 内容粘贴到编辑器中
4. （可选）进入 **Settings → Variables** 设置环境变量
5. 点击 **Save and deploy**

### 方式二：Wrangler CLI

```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

## 订阅链接

| 格式 | 链接 |
|------|------|
| 通用 Base64 | `https://你的域名/sub` |
| Clash-Meta | `https://你的域名/clash` |
| Sing-Box | `https://你的域名/singbox` |

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `proxyip` | ProxyIP 地址 | 无 |

> **注意**：Worker 不验证 Trojan 密码，客户端可填写任意密码连接。

## 自定义 ProxyIP

1. **全局变量**：在 Worker 环境变量中设置 `proxyip`
2. **单节点路径**：客户端路径使用 `/pyip=IP地址:端口`

## 推荐客户端

- **Android**: v2rayNG、Nekobox、Karing
- **Windows**: v2rayN、Hiddify、Karing
- **iOS**: Karing、Shadowrocket、Streisand
- **路由器**: passwall、ssr-plus、homeproxy

## 致谢

- [yonggekkk/Cloudflare-vless-trojan](https://github.com/yonggekkk/Cloudflare-vless-trojan) — Trojan 协议实现参考
- [emn178/js-sha256](https://github.com/emn178/js-sha256) — SHA-224/256 哈希库
- [cf.090227.xyz](https://cf.090227.xyz) — 优选域名服务