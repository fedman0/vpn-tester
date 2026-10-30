package com.arad.vpn_tester.parse

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

object SubscriptionFetcher {

    private const val MAX_BYTES = 16 * 1024 * 1024

    fun fetch(url: String, timeoutMs: Int): String? {
        val conn = runCatching { URL(url).openConnection() as HttpURLConnection }.getOrNull() ?: return null
        return try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = true
            conn.setRequestProperty("User-Agent", "v2rayNG/1.10.5")
            conn.setRequestProperty("Accept", "*/*")
            if (conn.responseCode !in 200..299) return null
            conn.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_BYTES) break
                }
                String(out.toByteArray(), Charsets.UTF_8)
            }
        } catch (_: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }
}
