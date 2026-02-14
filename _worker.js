// CF Trojan Worker — Trojan over WebSocket 代理 + 优选域名订阅
// 基于 cloudflare:sockets API，部署到 Cloudflare Workers/Pages
import { connect } from "cloudflare:sockets";

// ======================== 配置区 ========================
const CONFIG = {
    PASSWORD: "trojan",          // Trojan 密码，可通过环境变量 pswd 覆盖
    PROXY_IP: "",                // ProxyIP，可通过环境变量 proxyip 覆盖
    PROXY_PORT: "443",           // ProxyIP 端口
    CDN_HOST: "ygking.cf.090227.xyz", // 优选域名
    TLS_PORTS: [443, 8443, 2053, 2083, 2087, 2096],
    WS_PATH: "/?ed=2560",
};

let password = CONFIG.PASSWORD;
let proxyIP = CONFIG.PROXY_IP;
let proxyPort = CONFIG.PROXY_PORT;
let sha224Password = "";

// ======================== Worker 入口 ========================
export default {
    /**
     * HTTP 请求处理入口
     */
    async fetch(request, env, ctx) {
        try {
            // 读取环境变量
            password = env.pswd || CONFIG.PASSWORD;
            proxyIP = env.proxyip || CONFIG.PROXY_IP;

            // 解析 proxyIP:port
            if (proxyIP) {
                if (proxyIP.includes("]:")) {
                    const idx = proxyIP.lastIndexOf(":");
                    proxyPort = proxyIP.slice(idx + 1);
                    proxyIP = proxyIP.slice(0, idx);
                } else if (!proxyIP.includes("]")) {
                    [proxyIP, proxyPort = "443"] = proxyIP.split(":");
                }
            }

            sha224Password = sha256.sha224(password);

            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);

            // WebSocket 升级 → Trojan 代理
            if (upgradeHeader === "websocket") {
                // 支持路径动态设置 ProxyIP: /pyip=1.2.3.4
                if (url.pathname.includes("/pyip=")) {
                    const tmpIP = url.pathname.split("=")[1];
                    if (tmpIP) {
                        proxyIP = tmpIP;
                        if (proxyIP.includes("]:")) {
                            const idx = proxyIP.lastIndexOf(":");
                            proxyPort = proxyIP.slice(idx + 1);
                            proxyIP = proxyIP.slice(0, idx);
                        } else if (!proxyIP.includes("]")) {
                            [proxyIP, proxyPort = "443"] = proxyIP.split(":");
                        }
                    }
                }
                return await handleWsProxy(request);
            }

            // 非 WebSocket → 订阅/配置路由
            const hostName = request.headers.get("Host");
            switch (url.pathname) {
                case "/sub":
                    return handleSubRoute(hostName, "base64");
                case "/clash":
                    return handleSubRoute(hostName, "clash");
                case "/singbox":
                    return handleSubRoute(hostName, "singbox");
                default:
                    // 伪装：返回 CF 请求信息 JSON
                    return new Response(JSON.stringify(request.cf, null, 4), {
                        status: 200,
                        headers: { "Content-Type": "application/json;charset=utf-8" },
                    });
            }
        } catch (err) {
            return new Response(err.toString(), { status: 500 });
        }
    },
};

// ======================== 订阅路由处理 ========================

function handleSubRoute(hostName, format) {
    const cdnHost = CONFIG.CDN_HOST;
    switch (format) {
        case "base64":
            return new Response(generateSubConfig(password, hostName, cdnHost), {
                headers: { "Content-Type": "text/plain;charset=utf-8" },
            });
        case "clash":
            return new Response(generateClashConfig(password, hostName, cdnHost), {
                headers: { "Content-Type": "text/plain;charset=utf-8" },
            });
        case "singbox":
            return new Response(generateSingboxConfig(password, hostName, cdnHost), {
                headers: { "Content-Type": "application/json;charset=utf-8" },
            });
    }
}

// ======================== 订阅生成 ========================

/**
 * 生成 Base64 聚合通用订阅（trojan:// 链接）
 */
function generateSubConfig(pwd, host, cdnHost) {
    const lines = [];
    for (const port of CONFIG.TLS_PORTS) {
        const name = `CF_${cdnHost}_${port}`;
        lines.push(`trojan://${pwd}@${cdnHost}:${port}?security=tls&type=ws&host=${host}&sni=${host}&fp=randomized&path=%2F%3Fed%3D2560#${name}`);
    }
    return btoa(lines.join("\n"));
}

/**
 * 生成 Clash-Meta YAML 订阅配置
 */
function generateClashConfig(pwd, host, cdnHost) {
    const proxies = [];
    const proxyNames = [];

    for (const port of CONFIG.TLS_PORTS) {
        const name = `CF_${cdnHost}_${port}`;
        proxyNames.push(name);
        proxies.push(`- name: "${name}"
  type: trojan
  server: ${cdnHost}
  port: ${port}
  password: ${pwd}
  udp: false
  sni: ${host}
  network: ws
  ws-opts:
    path: "${CONFIG.WS_PATH}"
    headers:
      Host: ${host}`);
    }

    const proxyNamesYaml = proxyNames.map((n) => `    - "${n}"`).join("\n");

    return `port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
${proxies.join("\n\n")}

proxy-groups:
- name: "负载均衡"
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
${proxyNamesYaml}

- name: "自动选择"
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
${proxyNamesYaml}

- name: "🌍选择代理"
  type: select
  proxies:
    - "负载均衡"
    - "自动选择"
    - DIRECT
${proxyNamesYaml}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`;
}

/**
 * 生成 Sing-Box JSON 订阅配置
 */
function generateSingboxConfig(pwd, host, cdnHost) {
    const outbounds = [];
    const proxyTags = [];

    for (const port of CONFIG.TLS_PORTS) {
        const tag = `CF_${cdnHost}_${port}`;
        proxyTags.push(tag);
        outbounds.push({
            server: cdnHost,
            server_port: port,
            tag: tag,
            tls: {
                enabled: true,
                server_name: host,
                insecure: false,
                utls: { enabled: true, fingerprint: "chrome" },
            },
            transport: {
                headers: { Host: [host] },
                path: CONFIG.WS_PATH,
                type: "ws",
            },
            type: "trojan",
            password: pwd,
        });
    }

    const config = {
        log: { disabled: false, level: "info", timestamp: true },
        experimental: {
            clash_api: {
                external_controller: "127.0.0.1:9090",
                external_ui: "ui",
                secret: "",
                default_mode: "Rule",
            },
            cache_file: { enabled: true, path: "cache.db", store_fakeip: true },
        },
        dns: {
            servers: [
                { tag: "proxydns", address: "tls://8.8.8.8/dns-query", detour: "select" },
                { tag: "localdns", address: "h3://223.5.5.5/dns-query", detour: "direct" },
                { tag: "dns_fakeip", address: "fakeip" },
            ],
            rules: [
                { outbound: "any", server: "localdns", disable_cache: true },
                { clash_mode: "Global", server: "proxydns" },
                { clash_mode: "Direct", server: "localdns" },
                { rule_set: "geosite-cn", server: "localdns" },
                { rule_set: "geosite-geolocation-!cn", server: "proxydns" },
                { rule_set: "geosite-geolocation-!cn", query_type: ["A", "AAAA"], server: "dns_fakeip" },
            ],
            fakeip: { enabled: true, inet4_range: "198.18.0.0/15", inet6_range: "fc00::/18" },
            independent_cache: true,
            final: "proxydns",
        },
        inbounds: [
            {
                type: "tun",
                tag: "tun-in",
                address: ["172.19.0.1/30", "fd00::1/126"],
                auto_route: true,
                strict_route: true,
                sniff: true,
                sniff_override_destination: true,
                domain_strategy: "prefer_ipv4",
            },
        ],
        outbounds: [
            {
                tag: "select",
                type: "selector",
                default: "auto",
                outbounds: ["auto", ...proxyTags],
            },
            ...outbounds,
            { tag: "direct", type: "direct" },
            {
                tag: "auto",
                type: "urltest",
                outbounds: proxyTags,
                url: "https://www.gstatic.com/generate_204",
                interval: "1m",
                tolerance: 50,
                interrupt_exist_connections: false,
            },
        ],
        route: {
            rule_set: [
                {
                    tag: "geosite-geolocation-!cn",
                    type: "remote",
                    format: "binary",
                    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                    download_detour: "select",
                    update_interval: "1d",
                },
                {
                    tag: "geosite-cn",
                    type: "remote",
                    format: "binary",
                    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
                    download_detour: "select",
                    update_interval: "1d",
                },
                {
                    tag: "geoip-cn",
                    type: "remote",
                    format: "binary",
                    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                    download_detour: "select",
                    update_interval: "1d",
                },
            ],
            auto_detect_interface: true,
            final: "select",
            rules: [
                { inbound: "tun-in", action: "sniff" },
                { protocol: "dns", action: "hijack-dns" },
                { port: 443, network: "udp", action: "reject" },
                { clash_mode: "Direct", outbound: "direct" },
                { clash_mode: "Global", outbound: "select" },
                { rule_set: "geoip-cn", outbound: "direct" },
                { rule_set: "geosite-cn", outbound: "direct" },
                { ip_is_private: true, outbound: "direct" },
                { rule_set: "geosite-geolocation-!cn", outbound: "select" },
            ],
        },
        ntp: {
            enabled: true,
            server: "time.apple.com",
            server_port: 123,
            interval: "30m",
            detour: "direct",
        },
    };
    return JSON.stringify(config, null, 2);
}

// ======================== Trojan WebSocket 代理核心 ========================

/**
 * WebSocket 代理处理器：接受 WS 连接，解析 Trojan 协议，建立 TCP 出站
 */
async function handleWsProxy(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;

    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (udpStreamWrite) return udpStreamWrite(chunk);

                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    // 首次数据：解析 Trojan 头部
                    const { hasError, message, portRemote = 443, addressRemote = "", rawClientData } =
                        await parseTrojanHeader(chunk);
                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                    if (hasError) {
                        throw new Error(message);
                    }

                    handleTcpOutbound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, log);
                },
                close() {
                    log("readableWebSocketStream is closed");
                },
                abort(reason) {
                    log("readableWebSocketStream is aborted", JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("readableWebSocketStream pipeTo error", err);
        });

    return new Response(null, { status: 101, webSocket: client });
}

/**
 * 解析 Trojan 协议头
 * 格式: SHA224(密码) + CRLF + CMD(1B) + ATYP(1B) + 地址 + 端口(2B) + CRLF + 数据
 */
async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "invalid data" };
    }

    // 检查 SHA224 后的 CRLF
    if (
        new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d ||
        new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a
    ) {
        return { hasError: true, message: "invalid header format (missing CR LF)" };
    }

    // 校验密码
    const receivedPassword = new TextDecoder().decode(buffer.slice(0, 56));
    if (receivedPassword !== sha224Password) {
        return { hasError: true, message: "invalid password" };
    }

    // 解析 SOCKS5 风格的请求数据
    const socks5DataBuffer = buffer.slice(58); // 跳过密码 + CRLF
    if (socks5DataBuffer.byteLength < 6) {
        return { hasError: true, message: "invalid SOCKS5 request data" };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return { hasError: true, message: "unsupported command, only TCP (CONNECT) is allowed" };
    }

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let addressRemote = "";

    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            addressRemote = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // 域名
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            addressRemote = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressRemote = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!addressRemote) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }

    const portIndex = addressIndex + addressLength;
    const portRemote = new DataView(socks5DataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    return {
        hasError: false,
        addressRemote,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4), // 跳过端口(2B) + CRLF(2B)
    };
}

/**
 * 建立 TCP 出站连接，支持 ProxyIP 重试
 */
async function handleTcpOutbound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        const tcpSocket = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote);
        tcpSocket.closed
            .catch((error) => console.log("retry tcpSocket closed error", error))
            .finally(() => safeCloseWebSocket(webSocket));
        remoteSocketToWS(tcpSocket, webSocket, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

// ======================== 流管道工具函数 ========================

/**
 * 将 WebSocket 消息转为 ReadableStream
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
            // 处理 early data（通过 sec-websocket-protocol 头携带）
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) { },
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`readableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });
    return stream;
}

/**
 * 将远端 TCP 数据流转发到 WebSocket
 */
async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() { },
                async write(chunk, controller) {
                    hasIncomingData = true;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket connection is not open");
                    }
                    webSocket.send(chunk);
                },
                close() {
                    log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error("remoteSocket.readable abort", reason);
                },
            })
        )
        .catch((error) => {
            console.error("remoteSocketToWS error:", error.stack || error);
            safeCloseWebSocket(webSocket);
        });

    // 如果没有收到任何数据且有重试函数，则使用 ProxyIP 重试
    if (hasIncomingData === false && retry) {
        log("retry");
        retry();
    }
}

// ======================== 工具函数 ========================

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { error: null };
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

// ======================== SHA-256 / SHA-224 库 ========================
// js-sha256 v0.11.0 by Chen, Yi-Cyuan (MIT License)
// https://github.com/emn178/js-sha256

var sha256 = (function () {
    "use strict";

    var ERROR = "input is invalid type";
    var HEX_CHARS = "0123456789abcdef".split("");
    var EXTRA = [-2147483648, 8388608, 32768, 128];
    var SHIFT = [24, 16, 8, 0];
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    var blocks = [];

    function Sha256(is224, sharedMemory) {
        if (sharedMemory) {
            blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] =
                blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] =
                blocks[15] = 0;
            this.blocks = blocks;
        } else {
            this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        }

        if (is224) {
            this.h0 = 0xc1059ed8;
            this.h1 = 0x367cd507;
            this.h2 = 0x3070dd17;
            this.h3 = 0xf70e5939;
            this.h4 = 0xffc00b31;
            this.h5 = 0x68581511;
            this.h6 = 0x64f98fa7;
            this.h7 = 0xbefa4fa4;
        } else {
            this.h0 = 0x6a09e667;
            this.h1 = 0xbb67ae85;
            this.h2 = 0x3c6ef372;
            this.h3 = 0xa54ff53a;
            this.h4 = 0x510e527f;
            this.h5 = 0x9b05688c;
            this.h6 = 0x1f83d9ab;
            this.h7 = 0x5be0cd19;
        }

        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
        this.first = true;
        this.is224 = is224;
    }

    Sha256.prototype.update = function (message) {
        if (this.finalized) return;
        var notString = typeof message !== "string";
        if (notString && message.constructor === ArrayBuffer) {
            message = new Uint8Array(message);
        }
        var length = message.length;
        if (notString && (typeof length !== "number" || !Array.isArray(message) && !(message instanceof Uint8Array))) {
            throw new Error(ERROR);
        }
        var code,
            index = 0,
            i,
            blocks = this.blocks;
        while (index < length) {
            if (this.hashed) {
                this.hashed = false;
                blocks[0] = this.block;
                blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] =
                    blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            }
            if (notString) {
                for (i = this.start; index < length && i < 64; ++index) {
                    blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
                }
            } else {
                for (i = this.start; index < length && i < 64; ++index) {
                    code = message.charCodeAt(index);
                    if (code < 0x80) {
                        blocks[i >> 2] |= code << SHIFT[i++ & 3];
                    } else if (code < 0x800) {
                        blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    } else if (code < 0xd800 || code >= 0xe000) {
                        blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    } else {
                        code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
                        blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    }
                }
            }
            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= 64) {
                this.block = blocks[16];
                this.start = i - 64;
                this.hash();
                this.hashed = true;
            } else {
                this.start = i;
            }
        }
        if (this.bytes > 4294967295) {
            this.hBytes += (this.bytes / 4294967296) << 0;
            this.bytes = this.bytes % 4294967296;
        }
        return this;
    };

    Sha256.prototype.finalize = function () {
        if (this.finalized) return;
        this.finalized = true;
        var blocks = this.blocks,
            i = this.lastByteIndex;
        blocks[16] = this.block;
        blocks[i >> 2] |= EXTRA[i & 3];
        this.block = blocks[16];
        if (i >= 56) {
            if (!this.hashed) this.hash();
            blocks[0] = this.block;
            blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] =
                blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
        }
        blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
        blocks[15] = this.bytes << 3;
        this.hash();
    };

    Sha256.prototype.hash = function () {
        var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6, h = this.h7,
            blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;

        for (j = 16; j < 64; ++j) {
            t1 = blocks[j - 15];
            s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
            t1 = blocks[j - 2];
            s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
            blocks[j] = (blocks[j - 16] + s0 + blocks[j - 7] + s1) << 0;
        }

        for (j = 0; j < 64; j += 4) {
            if (this.first) {
                if (this.is224) {
                    ab = 300032;
                    t1 = blocks[0] - 1413257819;
                    h = (t1 - 150054599) << 0;
                    d = (t1 + 24177077) << 0;
                } else {
                    ab = 704751109;
                    t1 = blocks[0] - 210244248;
                    h = (t1 - 1521486534) << 0;
                    d = (t1 + 143694565) << 0;
                }
                this.first = false;
            } else {
                s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                ab = a & b;
                maj = ab ^ (a & c) ^ (b & c);
                ch = (e & f) ^ (~e & g);
                t1 = (h + s1 + ch + K[j] + blocks[j]) << 0;
                t2 = (s0 + maj) << 0;
                h = (d + t1) << 0;
                d = (t1 + t2) << 0;
            }
            s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
            s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
            da = d & a;
            maj = da ^ (d & b) ^ ab;
            ch = (h & e) ^ (~h & f);
            t1 = (g + s1 + ch + K[j + 1] + blocks[j + 1]) << 0;
            t2 = (s0 + maj) << 0;
            g = (c + t1) << 0;
            c = (t1 + t2) << 0;
            s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
            s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
            cd = c & d;
            maj = cd ^ (c & a) ^ da;
            ch = (g & h) ^ (~g & e);
            t1 = (f + s1 + ch + K[j + 2] + blocks[j + 2]) << 0;
            t2 = (s0 + maj) << 0;
            f = (b + t1) << 0;
            b = (t1 + t2) << 0;
            s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
            s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
            bc = b & c;
            maj = bc ^ (b & d) ^ cd;
            ch = (f & g) ^ (~f & h);
            t1 = (e + s1 + ch + K[j + 3] + blocks[j + 3]) << 0;
            t2 = (s0 + maj) << 0;
            e = (a + t1) << 0;
            a = (t1 + t2) << 0;
        }

        this.h0 = (this.h0 + a) << 0;
        this.h1 = (this.h1 + b) << 0;
        this.h2 = (this.h2 + c) << 0;
        this.h3 = (this.h3 + d) << 0;
        this.h4 = (this.h4 + e) << 0;
        this.h5 = (this.h5 + f) << 0;
        this.h6 = (this.h6 + g) << 0;
        this.h7 = (this.h7 + h) << 0;
    };

    Sha256.prototype.hex = function () {
        this.finalize();
        var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5, h6 = this.h6, h7 = this.h7;
        var hex =
            HEX_CHARS[(h0 >> 28) & 0x0f] + HEX_CHARS[(h0 >> 24) & 0x0f] +
            HEX_CHARS[(h0 >> 20) & 0x0f] + HEX_CHARS[(h0 >> 16) & 0x0f] +
            HEX_CHARS[(h0 >> 12) & 0x0f] + HEX_CHARS[(h0 >> 8) & 0x0f] +
            HEX_CHARS[(h0 >> 4) & 0x0f] + HEX_CHARS[h0 & 0x0f] +
            HEX_CHARS[(h1 >> 28) & 0x0f] + HEX_CHARS[(h1 >> 24) & 0x0f] +
            HEX_CHARS[(h1 >> 20) & 0x0f] + HEX_CHARS[(h1 >> 16) & 0x0f] +
            HEX_CHARS[(h1 >> 12) & 0x0f] + HEX_CHARS[(h1 >> 8) & 0x0f] +
            HEX_CHARS[(h1 >> 4) & 0x0f] + HEX_CHARS[h1 & 0x0f] +
            HEX_CHARS[(h2 >> 28) & 0x0f] + HEX_CHARS[(h2 >> 24) & 0x0f] +
            HEX_CHARS[(h2 >> 20) & 0x0f] + HEX_CHARS[(h2 >> 16) & 0x0f] +
            HEX_CHARS[(h2 >> 12) & 0x0f] + HEX_CHARS[(h2 >> 8) & 0x0f] +
            HEX_CHARS[(h2 >> 4) & 0x0f] + HEX_CHARS[h2 & 0x0f] +
            HEX_CHARS[(h3 >> 28) & 0x0f] + HEX_CHARS[(h3 >> 24) & 0x0f] +
            HEX_CHARS[(h3 >> 20) & 0x0f] + HEX_CHARS[(h3 >> 16) & 0x0f] +
            HEX_CHARS[(h3 >> 12) & 0x0f] + HEX_CHARS[(h3 >> 8) & 0x0f] +
            HEX_CHARS[(h3 >> 4) & 0x0f] + HEX_CHARS[h3 & 0x0f] +
            HEX_CHARS[(h4 >> 28) & 0x0f] + HEX_CHARS[(h4 >> 24) & 0x0f] +
            HEX_CHARS[(h4 >> 20) & 0x0f] + HEX_CHARS[(h4 >> 16) & 0x0f] +
            HEX_CHARS[(h4 >> 12) & 0x0f] + HEX_CHARS[(h4 >> 8) & 0x0f] +
            HEX_CHARS[(h4 >> 4) & 0x0f] + HEX_CHARS[h4 & 0x0f] +
            HEX_CHARS[(h5 >> 28) & 0x0f] + HEX_CHARS[(h5 >> 24) & 0x0f] +
            HEX_CHARS[(h5 >> 20) & 0x0f] + HEX_CHARS[(h5 >> 16) & 0x0f] +
            HEX_CHARS[(h5 >> 12) & 0x0f] + HEX_CHARS[(h5 >> 8) & 0x0f] +
            HEX_CHARS[(h5 >> 4) & 0x0f] + HEX_CHARS[h5 & 0x0f] +
            HEX_CHARS[(h6 >> 28) & 0x0f] + HEX_CHARS[(h6 >> 24) & 0x0f] +
            HEX_CHARS[(h6 >> 20) & 0x0f] + HEX_CHARS[(h6 >> 16) & 0x0f] +
            HEX_CHARS[(h6 >> 12) & 0x0f] + HEX_CHARS[(h6 >> 8) & 0x0f] +
            HEX_CHARS[(h6 >> 4) & 0x0f] + HEX_CHARS[h6 & 0x0f];
        if (!this.is224) {
            hex +=
                HEX_CHARS[(h7 >> 28) & 0x0f] + HEX_CHARS[(h7 >> 24) & 0x0f] +
                HEX_CHARS[(h7 >> 20) & 0x0f] + HEX_CHARS[(h7 >> 16) & 0x0f] +
                HEX_CHARS[(h7 >> 12) & 0x0f] + HEX_CHARS[(h7 >> 8) & 0x0f] +
                HEX_CHARS[(h7 >> 4) & 0x0f] + HEX_CHARS[h7 & 0x0f];
        }
        return hex;
    };

    Sha256.prototype.toString = Sha256.prototype.hex;

    function createMethod(is224) {
        var method = function (message) {
            return new Sha256(is224, true).update(message).hex();
        };
        return method;
    }

    return {
        sha256: createMethod(false),
        sha224: createMethod(true),
    };
})();
