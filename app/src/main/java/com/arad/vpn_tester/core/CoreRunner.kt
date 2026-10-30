package com.arad.vpn_tester.core

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

data class RunConfig(
    val urls: List<String>,
    val timeoutMs: Int,
    val concurrency: Int,
    val dns: List<String>,
)

data class CoreResult(
    val id: Long,
    val ok: Boolean,
    val delay: Long,
    val proto: String?,
    val engine: String?,
    val error: String?,
)

sealed interface CoreEvent {
    data class Result(val result: CoreResult) : CoreEvent
    data object Done : CoreEvent
}

class CoreRunner(private val context: Context) {

    @Volatile
    private var process: Process? = null

    val binary: File
        get() = File(context.applicationInfo.nativeLibraryDir, "libcore.so")

    fun isAvailable(): Boolean = binary.exists()

    fun stop() {
        process?.destroy()
    }

    fun run(config: RunConfig, jobs: List<Pair<Long, String>>): Flow<CoreEvent> = flow {
        val pb = ProcessBuilder(binary.absolutePath)
        pb.directory(context.filesDir)
        pb.environment()["HOME"] = context.filesDir.absolutePath
        pb.environment()["TMPDIR"] = context.cacheDir.absolutePath
        pb.environment()["SSL_CERT_DIR"] = "/system/etc/security/cacerts"
        pb.redirectError(File(context.cacheDir, "core.log"))
        val p = pb.start()
        process = p
        try {
            coroutineScope {
                val writer = launch(Dispatchers.IO) {
                    runCatching {
                        p.outputStream.bufferedWriter().use { w ->
                            w.write(configJson(config))
                            w.newLine()
                            for ((id, link) in jobs) {
                                w.write(JSONObject().put("id", id).put("link", link).toString())
                                w.newLine()
                            }
                        }
                    }
                }
                val reader = p.inputStream.bufferedReader()
                while (true) {
                    val line = runCatching { reader.readLine() }.getOrNull() ?: break
                    val obj = runCatching { JSONObject(line) }.getOrNull() ?: continue
                    if (obj.optBoolean("done")) {
                        emit(CoreEvent.Done)
                        break
                    }
                    emit(
                        CoreEvent.Result(
                            CoreResult(
                                id = obj.optLong("id"),
                                ok = obj.optBoolean("ok"),
                                delay = obj.optLong("delay"),
                                proto = obj.optString("proto").ifEmpty { null },
                                engine = obj.optString("engine").ifEmpty { null },
                                error = obj.optString("error").ifEmpty { null },
                            ),
                        ),
                    )
                }
                writer.cancel()
            }
        } finally {
            p.destroy()
            if (process === p) process = null
        }
    }.flowOn(Dispatchers.IO)

    private fun configJson(config: RunConfig): String = JSONObject()
        .put("urls", JSONArray(config.urls))
        .put("timeout", config.timeoutMs)
        .put("concurrency", config.concurrency)
        .put("dns", JSONArray(config.dns))
        .toString()
}
