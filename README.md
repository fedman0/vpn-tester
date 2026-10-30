# VPN Tester

Android app (Android 11+, no root) that tests large batches of VPN and proxy configs in parallel without bringing up a VPN tunnel.
Nothing touches the phone's routes, DNS or system proxy: every test runs inside an embedded core process.

## Test page

Paste links, subscription URLs or base64 blobs, press **Run test**, then **Copy active** to copy every working config sorted by ping.

Each config is loaded straight into the core and requests
`http://cp.cloudflare.com/generate_204` and `https://www.google.com/generate_204` at the same time; the first 204 answer is the ping.

Supported links: VLESS, VMess, Trojan, Trojan-Go, Shadowsocks (2022, obfs, v2ray-plugin, shadow-tls, kcptun, restls), ShadowsocksR,
SOCKS4/4a/5, HTTP/HTTPS, Hysteria, Hysteria2 (+Realm), TUIC, Juicity, AnyTLS, NaiveProxy (H2/QUIC), Brook,
SSH, Snell v1-v3, Mieru, MASQUE, TrustTunnel (`tt://`), ShadowTLS, MTProto (`tg://`, `t.me/proxy`), v2rayN inner links.
Transports: TCP, TLS, REALITY, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP, mKCP.

## Folder page

Pick a folder (optionally with subfolders), press **Scan & Test**. Every file is inspected by content (the extension alone never decides),
parsed into a common model, validated and tested in stages:

`Parse → DNS → Transport → Handshake → Authentication → Data probe`

Each config ends as Connectable / DataPlaneVerified or with the failing stage
(DNSFailed, HostUnreachable, PortUnreachable, HandshakeFailed, AuthenticationFailed, Invalid, Unsupported).
Connectable configs are pre-selected; **Save Connected Configs** copies them, together with the certificate, key and credential files they reference,
into a folder you choose, keeping relative paths. Files holding many configs (link lists, Clash, sing-box, Xray arrays, Surge, Loon, Quantumult X,
AnyConnect profiles, AmneziaVPN keys) are written back with only the selected entries. Duplicates are detected by fingerprint and can be hidden.

| Family | Files | Test |
|---|---|---|
| OpenVPN | `.ovpn`, `.conf` (+ ca/cert/key/tls-auth/tls-crypt/tls-crypt-v2/pkcs12/auth-user-pass files) | userspace OpenVPN client: TLS + key exchange, AUTH_FAILED / PUSH_REPLY, one request through the tunnel |
| WireGuard / AmneziaWG v1–v3 | `.conf`, `.wg`, `.awg` | in-process WireGuard device: real handshake (latest handshake), request through a userspace IP stack |
| AmneziaVPN | `vpn://` keys, `.vpn`, `.json` | every container dispatched to its tester |
| Xray / V2Ray | `.json` (JSONC), `.yaml`, `.toml`, config arrays | validated with Xray's loader, each proxy outbound tested |
| sing-box | `.json` | checked and converted, each outbound/endpoint tested |
| Clash / mihomo / Stash | `.yaml`, `.yml` | each proxy validated with mihomo and tested |
| Surge, Loon, Quantumult X | `.conf` | proxy lines converted and tested |
| IKEv2 / strongSwan | `.sswan`, `swanctl.conf`, `ipsec.conf` + `ipsec.secrets` | IKE_SA_INIT + IKE_AUTH (PSK, EAP-MSCHAPv2/MD5/GTC/TLS, certificates), then Delete |
| IKEv1 / Cisco IPsec / L2TP | `.pcf`, profiles above | Main/Aggressive Mode, PSK/RSA/hybrid, XAUTH |
| Apple profiles | `.mobileconfig` (plain or signed) | IKEv2, IPSec, L2TP and AnyConnect/GlobalProtect/Fortinet/Pulse/F5 payloads |
| NetworkManager | `.nmconnection` | OpenVPN, WireGuard, strongSwan, libreswan, vpnc, L2TP, OpenConnect, Fortinet, SSTP, PPTP |
| OpenConnect family | AnyConnect profile `.xml`, openconnect config, openfortivpn config | AnyConnect, GlobalProtect, Fortinet, Juniper, Pulse, F5, Array login without building a tunnel |
| SoftEther | `.vpn`, `vpn_client.config` | SoftEther handshake + login |
| SSTP / PPTP | via NetworkManager | SSTP + PPP MS-CHAPv2 login; PPTP control-connection handshake |
| Share links | any text file | same engines as the Test page |

Scripts, hooks and plugins inside configs (`up`, `down`, `PostUp`, `leftupdown`, …) are never executed; they are listed as warnings.
Passwords, keys and PSKs are masked in the UI and never logged.

## Building

The test core lives in `core/` (Go). It embeds Xray-core, mihomo, juicity and brook, plus native OpenVPN, WireGuard, IKEv1/IKEv2,
OpenConnect, SoftEther, SSTP, PPTP, MTProto and SOCKS4 testers. Build it before building the app:

```sh
core/build.sh
```

This writes `app/src/main/jniLibs/<abi>/libcore.so` for arm64-v8a, armeabi-v7a and x86_64. Then build the app from Android Studio as usual.

For debugging on a desktop: `go build -o core ./core && ./core scan -pretty <folder>` runs the whole folder pipeline in the terminal.
