package com.arad.vpn_tester.parse

import java.net.URI
import java.util.Base64

enum class Kind { PROXY, TUNNEL, ENCRYPTED, UNSUPPORTED }

data class ConfigLink(
    val link: String,
    val kind: Kind,
    val protocol: String,
    val name: String,
)

data class Extraction(
    val configs: List<ConfigLink>,
    val subscriptions: List<String>,
)

object LinkExtractor {

    private val proxySchemes = setOf(
        "vmess", "vless", "trojan", "trojan-go", "ss", "ssr",
        "socks", "socks4", "socks4a", "socks5", "socks5h", "http", "https",
        "hysteria", "hysteria2", "hy2", "hysteria2+realm", "hy2+realm", "realm",
        "hysteria2+realm+http", "hy2+realm+http", "realm+http",
        "tuic", "tuic5", "tuic4", "juicity", "anytls",
        "naive", "naive+https", "naive+quic", "naive+http2", "naive+h2", "naive+http3", "naive+h3",
        "brook", "ssh", "snell", "mieru", "mierus", "masque", "tt", "trusttunnel",
        "shadowtls", "shadow-tls", "stls", "tg", "v2rayn",
    )

    private val tunnelSchemes = setOf(
        "wireguard", "wg", "awg", "amneziawg", "openvpn", "ovpn", "dnstt", "dnst", "slipnet",
        "darktunnel", "slipstream", "iodine", "openconnect", "ikev2", "ipsec", "l2tp", "sstp",
        "softether", "tailscale", "zerotier",
    )

    private val encryptedSchemes = setOf("slipnet-enc", "slipnet-bundle-enc")

    private val wrapperSchemes = setOf(
        "v2raytun", "happ", "nekobox", "nekoray", "sn", "hiddify", "streisand", "karing",
        "clash", "clashmeta", "clashx", "sing-box", "v2rayng", "v2box", "foxray", "shadowrocket",
        "sub", "stash", "quantumult-x", "surge", "loon",
    )

    private val linkRegex = Regex("""(?i)(?<![A-Za-z0-9+.\-])([a-z][a-z0-9+.\-]{0,30})://[^\s"'<>`]+""")
    private val base64Chars = Regex("""^[A-Za-z0-9+/=_\-]+$""")
    private const val MAX_DEPTH = 4

    fun extract(text: String): Extraction {
        val configs = LinkedHashMap<String, ConfigLink>()
        val subs = LinkedHashSet<String>()
        walk(text, 0, configs, subs)
        return Extraction(configs.values.toList(), subs.toList())
    }

    private fun walk(text: String, depth: Int, configs: MutableMap<String, ConfigLink>, subs: MutableSet<String>) {
        if (depth > MAX_DEPTH) return
        if (!text.contains("://")) {
            val compact = text.filterNot { it.isWhitespace() }
            decodeBase64Text(compact)?.let { if (it.contains("://")) walk(it, depth + 1, configs, subs) }
            return
        }
        for (rawLine in text.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val matches = linkRegex.findAll(line).toList()
            if (matches.isEmpty()) {
                if (line.length >= 16) {
                    decodeBase64Text(line)?.let { if (it.contains("://")) walk(it, depth + 1, configs, subs) }
                }
                continue
            }
            if (matches.size == 1 && matches[0].range.first == 0 && matches[0].value.contains('#')) {
                handle(trimTail(line), depth, configs, subs)
                continue
            }
            for (m in matches) handle(trimTail(m.value), depth, configs, subs)
        }
    }

    private fun handle(link: String, depth: Int, configs: MutableMap<String, ConfigLink>, subs: MutableSet<String>) {
        val scheme = link.substringBefore("://").lowercase()
        if (link.length <= scheme.length + 3) return
        when {
            scheme == "http" || scheme == "https" -> {
                if (isTelegramProxy(link)) add(configs, link, Kind.PROXY)
                else if (isSubscription(link)) subs.add(link)
                else add(configs, link, Kind.PROXY)
            }
            scheme in proxySchemes -> add(configs, link, Kind.PROXY)
            scheme in tunnelSchemes -> add(configs, link, Kind.TUNNEL)
            scheme in encryptedSchemes -> add(configs, link, Kind.ENCRYPTED)
            scheme in wrapperSchemes -> {
                val body = link.substringAfter("://")
                if (scheme == "happ" && body.lowercase().startsWith("crypt")) {
                    add(configs, link, Kind.ENCRYPTED)
                    return
                }
                val inner = unwrap(body)
                if (inner != null) walk(inner, depth + 1, configs, subs)
                else add(configs, link, Kind.UNSUPPORTED)
            }
        }
    }

    private fun add(configs: MutableMap<String, ConfigLink>, link: String, kind: Kind) {
        if (configs.containsKey(link)) return
        configs[link] = ConfigLink(link, kind, protocolOf(link), nameOf(link))
    }

    fun trimTail(s: String): String {
        var end = s.length
        while (end > 0) {
            val c = s[end - 1]
            val drop = when (c) {
                '.', ',', ';', '!', '?', '"', '\'', '`', '»', '>', ']', '}' -> true
                ')' -> s.substring(0, end).count { it == '(' } < s.substring(0, end).count { it == ')' }
                else -> false
            }
            if (!drop) break
            end--
        }
        return s.substring(0, end)
    }

    private fun unwrap(body: String): String? {
        val decoded = percentDecode(body)
        val idx = decoded.indexOf("://")
        if (idx > 0) {
            var start = idx
            while (start > 0 && (decoded[start - 1].isLetterOrDigit() || decoded[start - 1] in "+.-")) start--
            if (start < idx) return decoded.substring(start)
        }
        val segment = decoded.substringBefore('#').substringBefore('?').trimEnd('/').substringAfterLast('/')
        return decodeBase64Text(segment)?.takeIf { it.contains("://") }
    }

    fun isTelegramProxy(link: String): Boolean {
        val rest = link.substringAfter("://").lowercase()
        return rest.startsWith("t.me/proxy") || rest.startsWith("t.me/socks") ||
            rest.startsWith("telegram.me/proxy") || rest.startsWith("telegram.me/socks") ||
            rest.startsWith("www.t.me/proxy")
    }

    fun isSubscription(link: String): Boolean {
        val rest = link.substringAfter("://").substringBefore('#')
        val authority = rest.substringBefore('/').substringBefore('?')
        if (authority.contains('@')) return false
        val tail = rest.substring(authority.length)
        if (tail.isEmpty() || tail == "/") return false
        return true
    }

    fun decodeBase64Text(s: String): String? {
        val t = s.trim()
        if (t.length < 8 || !base64Chars.matches(t)) return null
        val raw = t.trimEnd('=')
        val bytes = runCatching { Base64.getUrlDecoder().decode(raw.replace('+', '-').replace('/', '_')) }.getOrNull()
            ?: return null
        val out = String(bytes, Charsets.UTF_8)
        if (out.any { it == '�' }) return null
        return out
    }

    fun percentDecode(s: String): String {
        if (!s.contains('%')) return s
        val bytes = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val h = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (h != null) {
                    bytes.write(h)
                    i += 3
                    continue
                }
            }
            bytes.write(c.toString().toByteArray(Charsets.UTF_8))
            i++
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    fun protocolOf(link: String): String {
        val scheme = link.substringBefore("://").lowercase()
        return when (scheme) {
            "hy2", "hysteria2" -> "hysteria2"
            "hysteria2+realm", "hy2+realm", "realm", "hysteria2+realm+http", "hy2+realm+http", "realm+http" -> "hy2-realm"
            "socks", "socks5", "socks5h" -> "socks5"
            "tuic5", "tuic4" -> "tuic"
            "naive", "naive+https", "naive+http2", "naive+h2" -> "naive"
            "naive+quic", "naive+http3", "naive+h3" -> "naive-quic"
            "mierus" -> "mieru"
            "tt" -> "trusttunnel"
            "shadow-tls", "stls" -> "shadowtls"
            "tg" -> if (link.substringAfter("://").lowercase().startsWith("socks")) "socks5" else "mtproto"
            "http", "https" -> if (isTelegramProxy(link)) {
                if (link.lowercase().contains("/socks")) "socks5" else "mtproto"
            } else scheme
            "ss" -> if (ssMethod(link)?.startsWith("2022-") == true) "ss2022" else "ss"
            "v2rayn" -> "v2rayn/" + link.substringAfter("://").substringBefore('/').lowercase()
            else -> scheme
        }
    }

    private fun ssMethod(link: String): String? {
        val body = link.substringAfter("://").substringBefore('#').substringBefore('?')
        val at = body.lastIndexOf('@')
        val ui = if (at >= 0) percentDecode(body.substring(0, at)) else decodeBase64Text(body) ?: return null
        val plain = if (ui.contains(':')) ui else decodeBase64Text(ui) ?: return null
        return plain.substringBefore(':').lowercase()
    }

    fun nameOf(link: String): String {
        val scheme = link.substringBefore("://").lowercase()
        if (scheme == "vmess" && !link.contains('@')) {
            val json = decodeBase64Text(link.substringAfter("://").substringBefore('#').substringBefore('?'))
            if (json != null) {
                jsonField(json, "ps")?.takeIf { it.isNotBlank() }?.let { return it }
                jsonField(json, "add")?.let { add -> return add + ":" + (jsonField(json, "port") ?: "") }
            }
        }
        if (scheme == "ssr") {
            val decoded = decodeBase64Text(link.substringAfter("://"))
            if (decoded != null) {
                val remarks = decoded.substringAfter("remarks=", "").substringBefore('&')
                if (remarks.isNotEmpty()) decodeBase64Text(remarks)?.let { if (it.isNotBlank()) return it }
                return decoded.substringBefore(':') + ":" + decoded.substringAfter(':').substringBefore(':')
            }
        }
        val fragment = link.substringAfter('#', "")
        if (fragment.isNotBlank()) return percentDecode(fragment).trim()
        if (scheme == "tg" || scheme == "brook" || isTelegramProxy(link)) {
            Regex("""(?:server|wsserver|wssserver|quicserver)=([^&#]+)""").find(link)?.let { return percentDecode(it.groupValues[1]) }
        }
        return hostPortOf(link) ?: scheme
    }

    fun hostPortOf(link: String): String? {
        runCatching {
            val u = URI(link.substringBefore('#'))
            if (!u.host.isNullOrEmpty()) return if (u.port > 0) "${u.host}:${u.port}" else u.host
        }
        val rest = link.substringAfter("://").substringBefore('#').substringBefore('?')
        val hp = rest.substringAfterLast('@').substringBefore('/')
        if (hp.isNotEmpty() && hp.contains('.')) return hp
        Regex("""server=([^&]+)""").find(link)?.let { return percentDecode(it.groupValues[1]) }
        return null
    }

    private fun jsonField(json: String, key: String): String? {
        val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\"((?:\\\\.|[^\"\\\\])*)\"|[0-9]+)").find(json) ?: return null
        val raw = m.groupValues[2].ifEmpty { m.groupValues[1] }
        return unescapeJson(raw)
    }

    private fun unescapeJson(s: String): String {
        if (!s.contains('\\')) return s
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                when (val n = s[i + 1]) {
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    'r' -> sb.append('\r')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000c')
                    'u' -> {
                        val code = s.substring(i + 2, minOf(i + 6, s.length)).toIntOrNull(16)
                        if (code != null) {
                            sb.append(code.toChar())
                            i += 6
                            continue
                        }
                        sb.append(n)
                    }
                    else -> sb.append(n)
                }
                i += 2
                continue
            }
            sb.append(c)
            i++
        }
        return sb.toString()
    }
}
