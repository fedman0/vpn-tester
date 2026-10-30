package com.arad.vpn_tester.ui

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.arad.vpn_tester.core.CoreEvent
import com.arad.vpn_tester.core.CoreRunner
import com.arad.vpn_tester.core.RunConfig
import com.arad.vpn_tester.data.AppSettings
import com.arad.vpn_tester.data.Settings
import com.arad.vpn_tester.parse.ConfigLink
import com.arad.vpn_tester.parse.Kind
import com.arad.vpn_tester.parse.LinkExtractor
import com.arad.vpn_tester.parse.SubscriptionFetcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

enum class Status { PENDING, OK, FAIL, SKIPPED }

enum class Filter { ALL, WORKING, FAILED }

data class Entry(
    val id: Long,
    val link: String,
    val protocol: String,
    val name: String,
    val kind: Kind,
    val status: Status,
    val delay: Long = 0,
    val engine: String? = null,
    val error: String? = null,
)

data class UiState(
    val entries: List<Entry> = emptyList(),
    val running: Boolean = false,
    val phase: String? = null,
    val total: Int = 0,
    val tested: Int = 0,
    val working: Int = 0,
    val skipped: Int = 0,
    val subscriptions: Int = 0,
    val subscriptionsFailed: Int = 0,
    val filter: Filter = Filter.ALL,
    val vpnActive: Boolean = false,
    val message: String? = null,
)

class TesterViewModel(app: Application) : AndroidViewModel(app) {

    private val settingsStore = AppSettings(app)
    private val runner = CoreRunner(app)

    val input = TextFieldState()

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _settings = MutableStateFlow(settingsStore.load())
    val settings: StateFlow<Settings> = _settings.asStateFlow()

    private var job: Job? = null
    private var entries: Array<Entry> = emptyArray()
    private var indexById: Map<Long, Int> = emptyMap()
    @Volatile
    private var dirty = false

    fun setFilter(f: Filter) = _state.update { it.copy(filter = f) }

    fun consumeMessage() = _state.update { it.copy(message = null) }

    fun updateSettings(s: Settings) {
        _settings.value = s
        settingsStore.save(s)
    }

    fun clear() {
        if (_state.value.running) return
        entries = emptyArray()
        indexById = emptyMap()
        input.clearText()
        _state.update { UiState(filter = it.filter) }
    }

    fun stop() {
        job?.cancel()
        runner.stop()
    }

    fun run() {
        if (_state.value.running) return
        val text = input.text.toString()
        if (text.isBlank()) {
            _state.update { it.copy(message = "Paste some configs first") }
            return
        }
        if (!runner.isAvailable()) {
            _state.update { it.copy(message = "Test core is missing from this build (libcore.so)") }
            return
        }
        val cfg = _settings.value
        job = viewModelScope.launch {
            _state.update { it.copy(running = true, phase = "Reading configs…", entries = emptyList(), total = 0, tested = 0, working = 0, skipped = 0, subscriptions = 0, subscriptionsFailed = 0, vpnActive = vpnActive()) }
            try {
                val links = collectLinks(text, cfg)
                entries = links.mapIndexed { i, c ->
                    val testable = c.kind == Kind.PROXY
                    Entry(
                        id = i.toLong(),
                        link = c.link,
                        protocol = c.protocol,
                        name = c.name,
                        kind = c.kind,
                        status = if (testable) Status.PENDING else Status.SKIPPED,
                        error = when (c.kind) {
                            Kind.TUNNEL -> "Tunnel config — support coming later"
                            Kind.ENCRYPTED -> "Encrypted link — cannot be read"
                            Kind.UNSUPPORTED -> "Unsupported link"
                            Kind.PROXY -> null
                        },
                    )
                }.toTypedArray()
                indexById = entries.indices.associateBy { entries[it].id }
                publish(phase = null)
                if (entries.isEmpty()) {
                    _state.update { it.copy(message = "No configs found in the input") }
                    return@launch
                }
                testAll(cfg)
            } finally {
                runner.stop()
                publish(phase = null, running = false)
            }
        }
    }

    private suspend fun collectLinks(input: String, cfg: Settings): List<ConfigLink> = withContext(Dispatchers.Default) {
        val first = LinkExtractor.extract(input)
        val all = LinkedHashMap<String, ConfigLink>()
        first.configs.forEach { all[it.link] = it }
        if (cfg.fetchSubscriptions && first.subscriptions.isNotEmpty()) {
            _state.update { it.copy(phase = "Fetching ${first.subscriptions.size} subscription link(s)…", subscriptions = first.subscriptions.size) }
            val gate = Semaphore(6)
            val fetched = withContext(Dispatchers.IO) {
                first.subscriptions.map { url ->
                    async { gate.withPermit { SubscriptionFetcher.fetch(url, 12_000) } }
                }.awaitAll()
            }
            var failed = 0
            for (body in fetched) {
                if (body == null) {
                    failed++
                    continue
                }
                val ex = LinkExtractor.extract(body)
                if (ex.configs.isEmpty()) failed++
                ex.configs.forEach { if (!all.containsKey(it.link)) all[it.link] = it }
            }
            _state.update { it.copy(subscriptionsFailed = failed) }
        }
        all.values.toList()
    }

    private suspend fun testAll(cfg: Settings) {
        val runConfig = RunConfig(
            urls = cfg.urls.ifEmpty { listOf(Settings.DEFAULT_URL_1, Settings.DEFAULT_URL_2) },
            timeoutMs = cfg.timeoutMs,
            concurrency = cfg.concurrency,
            dns = systemDns(),
        )
        val publisher = viewModelScope.launch {
            while (isActive) {
                delay(150)
                if (dirty) publish()
            }
        }
        try {
            var attempts = 0
            while (attempts < 3) {
                val remaining = entries.filter { it.kind == Kind.PROXY && it.status == Status.PENDING }
                if (remaining.isEmpty()) break
                attempts++
                var finished = false
                runner.run(runConfig, remaining.map { it.id to it.link }).collect { ev ->
                    when (ev) {
                        is CoreEvent.Result -> applyResult(ev.result.id) { e ->
                            val r = ev.result
                            e.copy(
                                status = if (r.ok) Status.OK else Status.FAIL,
                                delay = r.delay,
                                engine = r.engine,
                                error = r.error,
                                protocol = r.proto ?: e.protocol,
                            )
                        }
                        CoreEvent.Done -> finished = true
                    }
                }
                if (finished) break
            }
            for (i in entries.indices) {
                if (entries[i].status == Status.PENDING) {
                    entries[i] = entries[i].copy(status = Status.FAIL, error = "Test core stopped unexpectedly")
                }
            }
            dirty = true
        } finally {
            publisher.cancel()
        }
    }

    private fun applyResult(id: Long, change: (Entry) -> Entry) {
        val idx = indexById[id] ?: return
        entries[idx] = change(entries[idx])
        dirty = true
    }

    private fun publish(phase: String? = _state.value.phase, running: Boolean = _state.value.running) {
        dirty = false
        val snapshot = entries.toList()
        val tested = snapshot.count { it.status == Status.OK || it.status == Status.FAIL }
        val working = snapshot.count { it.status == Status.OK }
        val skipped = snapshot.count { it.status == Status.SKIPPED }
        _state.update {
            it.copy(
                entries = snapshot,
                total = snapshot.size,
                tested = tested,
                working = working,
                skipped = skipped,
                phase = phase,
                running = running,
            )
        }
    }

    fun workingLinks(): List<String> = _state.value.entries
        .filter { it.status == Status.OK }
        .sortedBy { it.delay }
        .map { it.link }

    fun copyActive() {
        val links = workingLinks()
        if (links.isEmpty()) return
        copyText(links.joinToString("\n"))
        _state.update { it.copy(message = "Copied ${links.size} working config(s)") }
    }

    fun copyOne(link: String) {
        copyText(link)
        _state.update { it.copy(message = "Config copied") }
    }

    private fun copyText(text: String) {
        val cm = getApplication<Application>().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("configs", text))
    }

    fun pasteFromClipboard() {
        val cm = getApplication<Application>().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip ?: return
        val sb = StringBuilder()
        for (i in 0 until clip.itemCount) {
            clip.getItemAt(i).coerceToText(getApplication())?.let { sb.append(it).append('\n') }
        }
        val text = sb.toString().trim()
        if (text.isEmpty()) return
        input.edit {
            if (length > 0 && !toString().endsWith("\n")) append("\n")
            append(text)
        }
    }

    private fun connectivity(): ConnectivityManager =
        getApplication<Application>().getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private fun systemDns(): List<String> = runCatching {
        val cm = connectivity()
        val net = cm.activeNetwork ?: return emptyList()
        cm.getLinkProperties(net)?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
    }.getOrDefault(emptyList())

    private fun vpnActive(): Boolean = runCatching {
        val cm = connectivity()
        val net = cm.activeNetwork ?: return false
        cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    override fun onCleared() {
        runner.stop()
        super.onCleared()
    }
}
