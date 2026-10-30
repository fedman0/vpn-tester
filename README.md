# VPN Tester

Android app that tests large batches of proxy configs in parallel, without a VPN tunnel.
Paste links, subscription URLs or base64 blobs, press **Run test**, then **Copy active** to copy every working config sorted by ping.

Each config is loaded straight into an embedded core and requests
`http://cp.cloudflare.com/generate_204` and `https://www.google.com/generate_204` at the same time; the first 204 answer is the ping.

## Supported links

VLESS, VMess, Trojan, Trojan-Go, Shadowsocks (2022, obfs, v2ray-plugin, shadow-tls, kcptun, restls), ShadowsocksR,
SOCKS4/4a/5, HTTP/HTTPS, Hysteria, Hysteria2 (+Realm), TUIC, Juicity, AnyTLS, NaiveProxy (H2/QUIC), Brook,
SSH, Snell v1-v3, Mieru, MASQUE, TrustTunnel (`tt://`), ShadowTLS, MTProto (`tg://`, `t.me/proxy`), v2rayN inner links.
Transports: TCP, TLS, REALITY, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP, mKCP.

Tunnel configs (WireGuard, OpenVPN, DNS tunnels, …) are detected and listed but not tested yet.

## Building

The test core lives in `core/` (Go). It embeds Xray-core, mihomo, juicity and brook, plus native MTProto and SOCKS4 testers.
Build it before building the app:

```sh
core/build.sh
```

This writes `app/src/main/jniLibs/<abi>/libcore.so` for arm64-v8a, armeabi-v7a and x86_64. Then build the app from Android Studio as usual.
