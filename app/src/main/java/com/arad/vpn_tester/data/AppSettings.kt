package com.arad.vpn_tester.data

import android.content.Context

data class Settings(
    val url1: String = DEFAULT_URL_1,
    val url2: String = DEFAULT_URL_2,
    val timeoutMs: Int = 6000,
    val concurrency: Int = 64,
    val fetchSubscriptions: Boolean = true,
) {
    val urls: List<String> get() = listOf(url1, url2).map { it.trim() }.filter { it.startsWith("http://") || it.startsWith("https://") }.distinct()

    companion object {
        const val DEFAULT_URL_1 = "http://cp.cloudflare.com/generate_204"
        const val DEFAULT_URL_2 = "https://www.google.com/generate_204"
        val CONCURRENCY_STEPS = listOf(8, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512)
    }
}

class AppSettings(context: Context) {

    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun load(): Settings = Settings(
        url1 = prefs.getString("url1", null) ?: Settings.DEFAULT_URL_1,
        url2 = prefs.getString("url2", null) ?: Settings.DEFAULT_URL_2,
        timeoutMs = prefs.getInt("timeoutMs", 6000),
        concurrency = prefs.getInt("concurrency", 64),
        fetchSubscriptions = prefs.getBoolean("fetchSubscriptions", true),
    )

    fun save(s: Settings) {
        prefs.edit()
            .putString("url1", s.url1)
            .putString("url2", s.url2)
            .putInt("timeoutMs", s.timeoutMs)
            .putInt("concurrency", s.concurrency)
            .putBoolean("fetchSubscriptions", s.fetchSubscriptions)
            .apply()
    }
}
