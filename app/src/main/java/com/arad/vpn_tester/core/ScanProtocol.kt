package com.arad.vpn_tester.core

import org.json.JSONArray
import org.json.JSONObject

data class ScanOptions(
    val urls: List<String>,
    val dns: List<String>,
    val concurrency: Int,
    val dnsTimeoutMs: Int,
    val connectTimeoutMs: Int,
    val handshakeTimeoutMs: Int,
    val authTimeoutMs: Int,
    val overallTimeoutMs: Int,
    val dataProbe: Boolean,
) {
    fun toJson(): String = JSONObject()
        .put("urls", JSONArray(urls))
        .put("dns", JSONArray(dns))
        .put("concurrency", concurrency)
        .put(
            "timeouts",
            JSONObject()
                .put("dns", dnsTimeoutMs)
                .put("connect", connectTimeoutMs)
                .put("handshake", handshakeTimeoutMs)
                .put("auth", authTimeoutMs)
                .put("overall", overallTimeoutMs),
        )
        .put("dataProbe", dataProbe)
        .toString()
}

data class ScanConfig(
    val id: Int,
    val file: String,
    val index: Int,
    val multi: Boolean,
    val filterable: Boolean,
    val format: String,
    val protocol: String,
    val name: String,
    val host: String,
    val port: Int,
    val transport: String,
    val security: String,
    val sni: String,
    val username: String,
    val dependencies: List<String>,
    val certificates: List<String>,
    val fingerprint: String,
    val duplicateOf: Int,
    val warnings: List<String>,
    val status: String,
    val error: String?,
) {
    val fileName: String get() = file.substringAfterLast('/')
    val folder: String get() = if (file.contains('/')) file.substringBeforeLast('/') else ""

    companion object {
        fun from(o: JSONObject) = ScanConfig(
            id = o.optInt("id"),
            file = o.optString("file"),
            index = o.optInt("index"),
            multi = o.optBoolean("multi"),
            filterable = o.optBoolean("filterable"),
            format = o.optString("format"),
            protocol = o.optString("protocol"),
            name = o.optString("name"),
            host = o.optString("host"),
            port = o.optInt("port"),
            transport = o.optString("transport"),
            security = o.optString("security"),
            sni = o.optString("sni"),
            username = o.optString("username"),
            dependencies = o.optJSONArray("dependencies").strings(),
            certificates = o.optJSONArray("certificates").strings(),
            fingerprint = o.optString("fingerprint"),
            duplicateOf = o.optInt("duplicateOf"),
            warnings = o.optJSONArray("warnings").strings(),
            status = o.optString("status"),
            error = o.optString("error").ifEmpty { null },
        )
    }
}

data class Stages(
    val parse: Boolean?,
    val dns: Boolean?,
    val transport: Boolean?,
    val handshake: Boolean?,
    val authentication: Boolean?,
    val dataPlane: Boolean?,
)

data class ScanResult(
    val id: Int,
    val stages: Stages,
    val result: String,
    val latency: Long,
    val errorCode: String?,
    val errorMessage: String?,
    val isConnectable: Boolean,
    val engine: String?,
    val note: String?,
    val address: String?,
) {
    companion object {
        fun from(o: JSONObject): ScanResult {
            val s = o.optJSONObject("stages") ?: JSONObject()
            fun flag(k: String): Boolean? = if (!s.has(k) || s.isNull(k)) null else s.optBoolean(k)
            return ScanResult(
                id = o.optInt("id"),
                stages = Stages(flag("parse"), flag("dns"), flag("transport"), flag("handshake"), flag("authentication"), flag("dataPlane")),
                result = o.optString("result"),
                latency = o.optLong("latency"),
                errorCode = o.optString("errorCode").ifEmpty { null },
                errorMessage = o.optString("errorMessage").ifEmpty { null },
                isConnectable = o.optBoolean("isConnectable"),
                engine = o.optString("engine").ifEmpty { null },
                note = o.optString("note").ifEmpty { null },
                address = o.optString("address").ifEmpty { null },
            )
        }
    }
}

sealed interface ScanEvent {
    data class FileSent(val sent: Int, val total: Int) : ScanEvent
    data class Config(val config: ScanConfig) : ScanEvent
    data class Summary(val files: Int, val configs: Int, val dependencies: Int, val ignored: Int) : ScanEvent
    data class Testing(val id: Int) : ScanEvent
    data class Result(val result: ScanResult) : ScanEvent
    data class Done(val error: String?) : ScanEvent
}

data class FilterRequest(val path: String, val format: String, val data: ByteArray, val indices: List<Int>)

private fun JSONArray?.strings(): List<String> {
    if (this == null) return emptyList()
    return (0 until length()).mapNotNull { optString(it).ifEmpty { null } }
}
