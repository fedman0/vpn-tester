package com.arad.vpn_tester.core

import android.content.Context
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
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

    private fun start(vararg args: String): Process {
        val pb = ProcessBuilder(listOf(binary.absolutePath) + args)
        pb.directory(context.filesDir)
        pb.environment()["HOME"] = context.filesDir.absolutePath
        pb.environment()["TMPDIR"] = context.cacheDir.absolutePath
        pb.environment()["SSL_CERT_DIR"] = "/system/etc/security/cacerts"
        pb.redirectError(File(context.cacheDir, if (args.isEmpty()) "core.log" else "core-${args[0]}.log"))
        return pb.start()
    }

    fun <T> scan(options: ScanOptions, files: List<T>, pathOf: (T) -> String, read: (T) -> ByteArray?): Flow<ScanEvent> = channelFlow {
        val p = start("files")
        process = p
        val writer = launch(Dispatchers.IO) {
            runCatching {
                p.outputStream.bufferedWriter().use { w ->
                    w.write(options.toJson())
                    w.newLine()
                    var sent = 0
                    for (f in files) {
                        val data = runCatching { read(f) }.getOrNull()
                        sent++
                        if (data != null) {
                            w.write(
                                JSONObject()
                                    .put("path", pathOf(f))
                                    .put("data", Base64.encodeToString(data, Base64.NO_WRAP))
                                    .toString(),
                            )
                            w.newLine()
                        }
                        if (sent % 16 == 0 || sent == files.size) send(ScanEvent.FileSent(sent, files.size))
                    }
                    w.write("{\"end\":true}")
                    w.newLine()
                    w.flush()
                }
            }
        }
        val reader = launch(Dispatchers.IO) {
            val r = p.inputStream.bufferedReader()
            var done = false
            while (true) {
                val line = runCatching { r.readLine() }.getOrNull() ?: break
                val o = runCatching { JSONObject(line) }.getOrNull() ?: continue
                when (o.optString("ev")) {
                    "config" -> send(ScanEvent.Config(ScanConfig.from(o)))
                    "summary" -> send(ScanEvent.Summary(o.optInt("files"), o.optInt("configs"), o.optInt("dependencies"), o.optInt("ignored")))
                    "testing" -> send(ScanEvent.Testing(o.optInt("id")))
                    "result" -> send(ScanEvent.Result(ScanResult.from(o)))
                    "done" -> {
                        done = true
                        send(ScanEvent.Done(o.optString("error").ifEmpty { null }))
                    }
                }
                if (done) break
            }
            if (!done) send(ScanEvent.Done("Test core stopped unexpectedly"))
            writer.cancel()
            close()
        }
        awaitClose {
            reader.cancel()
            writer.cancel()
            p.destroy()
            if (process === p) process = null
        }
    }.flowOn(Dispatchers.IO)

    fun filter(requests: List<FilterRequest>): Map<String, ByteArray> {
        if (requests.isEmpty()) return emptyMap()
        val p = start("export")
        val out = HashMap<String, ByteArray>()
        try {
            val writer = Thread {
                runCatching {
                    p.outputStream.bufferedWriter().use { w ->
                        for (r in requests) {
                            w.write(
                                JSONObject()
                                    .put("path", r.path)
                                    .put("format", r.format)
                                    .put("data", Base64.encodeToString(r.data, Base64.NO_WRAP))
                                    .put("indices", JSONArray(r.indices))
                                    .toString(),
                            )
                            w.newLine()
                        }
                    }
                }
            }
            writer.start()
            p.inputStream.bufferedReader().useLines { lines ->
                for (line in lines) {
                    val o = runCatching { JSONObject(line) }.getOrNull() ?: continue
                    if (o.optBoolean("done")) break
                    if (o.optBoolean("ok")) {
                        out[o.optString("path")] = Base64.decode(o.optString("data"), Base64.DEFAULT)
                    }
                }
            }
            writer.join(2000)
        } finally {
            p.destroy()
        }
        return out
    }

    fun run(config: RunConfig, jobs: List<Pair<Long, String>>): Flow<CoreEvent> = flow {
        val p = start()
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
