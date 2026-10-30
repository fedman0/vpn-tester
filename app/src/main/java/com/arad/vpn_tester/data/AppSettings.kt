package com.arad.vpn_tester.data

import android.content.Context

data class Settings(
    val url1: String = DEFAULT_URL_1,
    val url2: String = DEFAULT_URL_2,
    val timeoutMs: Int = 6000,
    val concurrency: Int = 64,
    val fetchSubscriptions: Boolean = true,
    val folderConcurrency: Int = 10,
    val folderOverallMs: Int = 15000,
    val folderDnsMs: Int = 4000,
    val folderConnectMs: Int = 5000,
    val folderHandshakeMs: Int = 8000,
    val folderAuthMs: Int = 10000,
    val folderDataProbe: Boolean = true,
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

    fun load(): Settings {
        val d = Settings()
        return Settings(
            url1 = prefs.getString("url1", null) ?: Settings.DEFAULT_URL_1,
            url2 = prefs.getString("url2", null) ?: Settings.DEFAULT_URL_2,
            timeoutMs = prefs.getInt("timeoutMs", d.timeoutMs),
            concurrency = prefs.getInt("concurrency", d.concurrency),
            fetchSubscriptions = prefs.getBoolean("fetchSubscriptions", d.fetchSubscriptions),
            folderConcurrency = prefs.getInt("folderConcurrency", d.folderConcurrency),
            folderOverallMs = prefs.getInt("folderOverallMs", d.folderOverallMs),
            folderDnsMs = prefs.getInt("folderDnsMs", d.folderDnsMs),
            folderConnectMs = prefs.getInt("folderConnectMs", d.folderConnectMs),
            folderHandshakeMs = prefs.getInt("folderHandshakeMs", d.folderHandshakeMs),
            folderAuthMs = prefs.getInt("folderAuthMs", d.folderAuthMs),
            folderDataProbe = prefs.getBoolean("folderDataProbe", d.folderDataProbe),
        )
    }

    fun save(s: Settings) {
        prefs.edit()
            .putString("url1", s.url1)
            .putString("url2", s.url2)
            .putInt("timeoutMs", s.timeoutMs)
            .putInt("concurrency", s.concurrency)
            .putBoolean("fetchSubscriptions", s.fetchSubscriptions)
            .putInt("folderConcurrency", s.folderConcurrency)
            .putInt("folderOverallMs", s.folderOverallMs)
            .putInt("folderDnsMs", s.folderDnsMs)
            .putInt("folderConnectMs", s.folderConnectMs)
            .putInt("folderHandshakeMs", s.folderHandshakeMs)
            .putInt("folderAuthMs", s.folderAuthMs)
            .putBoolean("folderDataProbe", s.folderDataProbe)
            .apply()
    }

    fun lastFolder(): String? = prefs.getString("lastFolder", null)

    fun setLastFolder(uri: String?) {
        prefs.edit().putString("lastFolder", uri).apply()
    }

    fun scanSubfolders(): Boolean = prefs.getBoolean("scanSubfolders", true)

    fun setScanSubfolders(v: Boolean) {
        prefs.edit().putBoolean("scanSubfolders", v).apply()
    }
}
