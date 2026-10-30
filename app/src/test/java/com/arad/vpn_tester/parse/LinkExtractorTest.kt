package com.arad.vpn_tester.parse

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class LinkExtractorTest {

    private val vless = "vless://11111111-2222-3333-4444-555555555555@proxy.example.com:443?encryption=none&security=tls&type=ws&host=cdn.example.com&path=%2Fws&sni=cdn.example.com#Demo-VLESS"
    private val vmess = "vmess://eyJ2IjoiMiIsInBzIjoiZGVtby12bWVzcyIsImFkZCI6InByb3h5LmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImNkbi5leGFtcGxlLmNvbSIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJjZG4uZXhhbXBsZS5jb20iLCJhbHBuIjoiaDIsaHR0cC8xLjEiLCJmcCI6ImNocm9tZSJ9"
    private val ssr = "ssr://cHJveHkuZXhhbXBsZS5jb206NDQzOm9yaWdpbjphZXMtMjU2LWNmYjpwbGFpbjpaR1Z0Ynkxd1lYTnovP3JlbWFya3M9WkdWdGJ5MXpjM0kmb2Jmc3BhcmFtPVkyUnVMbVY0WVcxd2JHVXVZMjl0"

    @Test
    fun extractsMixedLinksAndSkipsNoise() {
        val text = """
            # VLESS
            $vless
            some chat text and a channel https://t.me/mychannel
            ($vmess)
            ss://2022-blake3-aes-256-gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@proxy.example.com:443#SS2022
            dnstt://d.example.com/?pubkey=0123&resolver=8.8.8.8:53#DNSTT
            happ://crypt3/AAAAencrypted
        """.trimIndent()
        val ex = LinkExtractor.extract(text)
        val byProto = ex.configs.associateBy { it.protocol }
        assertEquals(Kind.PROXY, byProto["vless"]?.kind)
        assertEquals("Demo-VLESS", byProto["vless"]?.name)
        assertEquals("demo-vmess", byProto["vmess"]?.name)
        assertEquals(vmess, byProto["vmess"]?.link)
        assertEquals("ss2022", byProto["ss2022"]?.protocol)
        assertEquals(Kind.TUNNEL, byProto["dnstt"]?.kind)
        assertEquals(Kind.ENCRYPTED, byProto["happ"]?.kind)
        assertEquals(listOf("https://t.me/mychannel"), ex.subscriptions)
    }

    @Test
    fun keepsSpacesInsideFragment() {
        val line = "trojan://pw@1.2.3.4:443?security=tls#🇩🇪 Germany 1"
        val ex = LinkExtractor.extract(line)
        assertEquals(1, ex.configs.size)
        assertEquals(line, ex.configs[0].link)
        assertEquals("🇩🇪 Germany 1", ex.configs[0].name)
    }

    @Test
    fun decodesBase64Subscription() {
        val body = "$vless\n$ssr\n"
        val blob = Base64.getEncoder().encodeToString(body.toByteArray())
        val ex = LinkExtractor.extract(blob)
        assertEquals(2, ex.configs.size)
        assertEquals("demo-ssr", ex.configs[1].name)
    }

    @Test
    fun unwrapsDeepLinks() {
        val wrapped = "v2raytun://import/" + java.net.URLEncoder.encode(vless, "UTF-8")
        val ex = LinkExtractor.extract(wrapped)
        assertEquals(1, ex.configs.size)
        assertEquals("vless", ex.configs[0].protocol)
    }

    @Test
    fun classifiesHttpLinks() {
        assertTrue(LinkExtractor.isSubscription("https://sub.example.com/api/v1/client/subscribe?token=abc"))
        assertTrue(!LinkExtractor.isSubscription("https://demo:password@proxy.example.com:443"))
        assertTrue(!LinkExtractor.isSubscription("http://1.2.3.4:8080"))
        val ex = LinkExtractor.extract("https://t.me/proxy?server=proxy.example.com&port=443&secret=0123456789abcdef0123456789abcdef")
        assertEquals("mtproto", ex.configs.single().protocol)
        assertEquals("proxy.example.com", ex.configs.single().name)
    }

    @Test
    fun deduplicates() {
        val ex = LinkExtractor.extract("$vless\n$vless\n$vless")
        assertEquals(1, ex.configs.size)
    }

    @Test
    fun protocolLabels() {
        assertEquals("hysteria2", LinkExtractor.protocolOf("hy2://pw@h:443"))
        assertEquals("naive-quic", LinkExtractor.protocolOf("naive+quic://u:p@h:443"))
        assertEquals("socks5", LinkExtractor.protocolOf("socks://dTpw@h:1080"))
        assertEquals("trusttunnel", LinkExtractor.protocolOf("tt://?AAEC"))
        assertEquals("hy2-realm", LinkExtractor.protocolOf("hysteria2+realm+http://t@h/r"))
    }
}
