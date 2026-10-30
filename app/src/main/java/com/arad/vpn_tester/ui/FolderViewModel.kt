package com.arad.vpn_tester.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Uri
import androidx.core.net.toUri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.arad.vpn_tester.core.CoreRunner
import com.arad.vpn_tester.core.FilterRequest
import com.arad.vpn_tester.core.ScanConfig
import com.arad.vpn_tester.core.ScanEvent
import com.arad.vpn_tester.core.ScanOptions
import com.arad.vpn_tester.core.ScanResult
import com.arad.vpn_tester.data.AppSettings
import com.arad.vpn_tester.data.Settings
import com.arad.vpn_tester.scan.ExportItem
import com.arad.vpn_tester.scan.FolderFile
import com.arad.vpn_tester.scan.FolderScanner
import com.arad.vpn_tester.scan.SafConfigExporter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class RowStatus { PENDING, TESTING, CONNECTABLE, FAILED, INVALID, UNSUPPORTED }

enum class FolderFilter { ALL, CONNECTABLE, FAILED, INVALID, UNSUPPORTED }

data class ScanRow(
    val config: ScanConfig,
    val status: RowStatus,
    val result: ScanResult? = null,
)

data class FolderUiState(
    val folderUri: Uri? = null,
    val folderLabel: String? = null,
    val scanSubfolders: Boolean = true,
    val running: Boolean = false,
    val saving: Boolean = false,
    val finished: Boolean = false,
    val phase: String? = null,
    val progress: Float? = null,
    val filesFound: Int = 0,
    val configs: Int = 0,
    val valid: Int = 0,
    val connectable: Int = 0,
    val failed: Int = 0,
    val invalid: Int = 0,
    val unsupported: Int = 0,
    val tested: Int = 0,
    val testable: Int = 0,
    val duplicates: Int = 0,
    val dependencies: Int = 0,
    val rows: List<ScanRow> = emptyList(),
    val selected: Set<Int> = emptySet(),
    val filter: FolderFilter = FolderFilter.ALL,
    val query: String = "",
    val removeDuplicates: Boolean = false,
    val message: String? = null,
)

class FolderViewModel(app: Application) : AndroidViewModel(app) {

    private val settingsStore = AppSettings(app)
    private val runner = CoreRunner(app)

    private val _state = MutableStateFlow(FolderUiState(scanSubfolders = settingsStore.scanSubfolders()))
    val state: StateFlow<FolderUiState> = _state.asStateFlow()

    private var job: Job? = null
    private var rows: ArrayList<ScanRow> = ArrayList()
    private var indexById: HashMap<Int, Int> = HashMap()
    private var selected: HashSet<Int> = HashSet()
    private var fileUris: Map<String, Uri> = emptyMap()
    private var filesFound = 0
    private var dependencies = 0

    @Volatile
    private var dirty = false

    init {
        settingsStore.lastFolder()?.let { s ->
            val uri = s.toUri()
            val granted = app.contentResolver.persistedUriPermissions.any { it.uri == uri && it.isReadPermission }
            if (granted) _state.update { it.copy(folderUri = uri, folderLabel = FolderScanner.label(uri)) }
        }
    }

    fun consumeMessage() = _state.update { it.copy(message = null) }

    fun setFilter(f: FolderFilter) = _state.update { it.copy(filter = f) }

    fun setQuery(q: String) = _state.update { it.copy(query = q) }

    fun setScanSubfolders(v: Boolean) {
        settingsStore.setScanSubfolders(v)
        _state.update { it.copy(scanSubfolders = v) }
    }

    fun setRemoveDuplicates(v: Boolean) {
        if (v) {
            rows.filter { it.config.duplicateOf != 0 }.forEach { selected.remove(it.config.id) }
        }
        _state.update { it.copy(removeDuplicates = v) }
        publish()
    }

    fun onFolderPicked(uri: Uri?) {
        uri ?: return
        val cr = getApplication<Application>().contentResolver
        runCatching { cr.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        settingsStore.setLastFolder(uri.toString())
        _state.update { it.copy(folderUri = uri, folderLabel = FolderScanner.label(uri)) }
    }

    fun toggle(id: Int) {
        if (!selected.add(id)) selected.remove(id)
        publish()
    }

    fun selectAllConnected() {
        val hideDup = _state.value.removeDuplicates
        rows.forEach {
            if (it.status == RowStatus.CONNECTABLE && !(hideDup && it.config.duplicateOf != 0)) selected.add(it.config.id)
        }
        publish()
    }

    fun clearSelection() {
        selected.clear()
        publish()
    }

    fun stop() {
        job?.cancel()
        runner.stop()
    }

    fun scanAndTest() {
        val st = _state.value
        if (st.running || st.saving) return
        val tree = st.folderUri
        if (tree == null) {
            _state.update { it.copy(message = "Select a folder first") }
            return
        }
        if (!runner.isAvailable()) {
            _state.update { it.copy(message = "Test core is missing from this build (libcore.so)") }
            return
        }
        val cfg = settingsStore.load()
        val ctx = getApplication<Application>()
        job = viewModelScope.launch {
            rows = ArrayList()
            indexById = HashMap()
            selected = HashSet()
            filesFound = 0
            dependencies = 0
            _state.update {
                it.copy(
                    running = true, finished = false, phase = "Discovering files…", progress = null,
                    rows = emptyList(), selected = emptySet(), filesFound = 0, configs = 0, valid = 0,
                    connectable = 0, failed = 0, invalid = 0, unsupported = 0, tested = 0, testable = 0,
                    duplicates = 0, dependencies = 0,
                )
            }
            val publisher = launch {
                while (isActive) {
                    delay(150)
                    if (dirty) publish()
                }
            }
            try {
                val files = withContext(Dispatchers.IO) {
                    FolderScanner.list(ctx, tree, st.scanSubfolders, { isActive }) { n ->
                        _state.update { it.copy(phase = "Discovering files… $n") }
                    }
                }
                fileUris = files.associate { it.path to it.uri }
                filesFound = files.size
                _state.update { it.copy(filesFound = files.size) }
                if (files.isEmpty()) {
                    _state.update { it.copy(message = "No readable files in this folder") }
                    return@launch
                }
                _state.update { it.copy(phase = "Reading ${files.size} files…", progress = 0f) }
                var finished = false
                runner.scan(scanOptions(cfg), files, FolderFile::path) { FolderScanner.read(ctx, it.uri) }.collect { ev ->
                    when (ev) {
                        is ScanEvent.FileSent -> _state.update {
                            it.copy(phase = "Reading files ${ev.sent} / ${ev.total}", progress = ev.sent.toFloat() / ev.total.coerceAtLeast(1))
                        }
                        is ScanEvent.Config -> {
                            val c = ev.config
                            val status = when (c.status) {
                                "Parsed" -> RowStatus.PENDING
                                "Invalid" -> RowStatus.INVALID
                                else -> RowStatus.UNSUPPORTED
                            }
                            indexById[c.id] = rows.size
                            rows.add(ScanRow(c, status))
                            dirty = true
                        }
                        is ScanEvent.Summary -> {
                            dependencies = ev.dependencies
                            _state.update { it.copy(phase = null, progress = null) }
                            dirty = true
                        }
                        is ScanEvent.Testing -> change(ev.id) { it.copy(status = RowStatus.TESTING) }
                        is ScanEvent.Result -> {
                            val r = ev.result
                            change(r.id) { row ->
                                val status = when {
                                    r.isConnectable -> RowStatus.CONNECTABLE
                                    r.result == "Unsupported" -> RowStatus.UNSUPPORTED
                                    r.result == "Invalid" -> RowStatus.INVALID
                                    else -> RowStatus.FAILED
                                }
                                row.copy(status = status, result = r)
                            }
                            val row = indexById[r.id]?.let { rows[it] }
                            if (r.isConnectable && row != null && !(_state.value.removeDuplicates && row.config.duplicateOf != 0)) {
                                selected.add(r.id)
                            }
                        }
                        is ScanEvent.Done -> {
                            finished = ev.error == null
                            ev.error?.let { e -> _state.update { it.copy(message = e) } }
                        }
                    }
                }
                for (i in rows.indices) {
                    val s = rows[i].status
                    if (s == RowStatus.PENDING || s == RowStatus.TESTING) {
                        rows[i] = rows[i].copy(status = RowStatus.FAILED, result = null)
                    }
                }
                dirty = true
                if (finished) _state.update { it.copy(finished = true) }
            } finally {
                publisher.cancel()
                runner.stop()
                _state.update { it.copy(running = false, phase = null, progress = null) }
                publish()
            }
        }
    }

    private fun scanOptions(cfg: Settings) = ScanOptions(
        urls = cfg.urls.ifEmpty { listOf(Settings.DEFAULT_URL_1, Settings.DEFAULT_URL_2) },
        dns = systemDns(),
        concurrency = cfg.folderConcurrency,
        dnsTimeoutMs = cfg.folderDnsMs,
        connectTimeoutMs = cfg.folderConnectMs,
        handshakeTimeoutMs = cfg.folderHandshakeMs,
        authTimeoutMs = cfg.folderAuthMs,
        overallTimeoutMs = cfg.folderOverallMs,
        dataProbe = cfg.folderDataProbe,
    )

    private fun change(id: Int, f: (ScanRow) -> ScanRow) {
        val i = indexById[id] ?: return
        rows[i] = f(rows[i])
        dirty = true
    }

    private fun publish() {
        dirty = false
        val snapshot = rows.toList()
        val removeDup = _state.value.removeDuplicates
        _state.update {
            it.copy(
                rows = snapshot,
                selected = HashSet(selected),
                filesFound = filesFound,
                configs = snapshot.size,
                valid = snapshot.count { r -> r.config.status == "Parsed" },
                connectable = snapshot.count { r -> r.status == RowStatus.CONNECTABLE && !(removeDup && r.config.duplicateOf != 0) },
                failed = snapshot.count { r -> r.status == RowStatus.FAILED },
                invalid = snapshot.count { r -> r.status == RowStatus.INVALID },
                unsupported = snapshot.count { r -> r.status == RowStatus.UNSUPPORTED },
                tested = snapshot.count { r -> r.result != null },
                testable = snapshot.count { r -> r.config.status == "Parsed" },
                duplicates = snapshot.count { r -> r.config.duplicateOf != 0 },
                dependencies = dependencies,
            )
        }
    }

    fun saveSelected(dest: Uri?) {
        dest ?: return
        val st = _state.value
        if (st.running || st.saving) return
        val hideDup = st.removeDuplicates
        val chosen = rows.filter { it.config.id in selected && !(hideDup && it.config.duplicateOf != 0) }
        if (chosen.isEmpty()) {
            _state.update { it.copy(message = "Nothing selected") }
            return
        }
        val ctx = getApplication<Application>()
        runCatching {
            ctx.contentResolver.takePersistableUriPermission(dest, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        }
        viewModelScope.launch {
            _state.update { it.copy(saving = true, phase = "Saving ${chosen.size} config(s)…") }
            try {
                val report = withContext(Dispatchers.IO) {
                    val byFile = chosen.groupBy { it.config.file }
                    val filterReqs = ArrayList<FilterRequest>()
                    for ((file, list) in byFile) {
                        val filterable = list.any { it.config.multi && it.config.filterable }
                        if (!filterable) continue
                        val uri = fileUris[file] ?: continue
                        val data = FolderScanner.read(ctx, uri) ?: continue
                        filterReqs.add(FilterRequest(file, list.first().config.format, data, list.map { it.config.index }.distinct().sorted()))
                    }
                    val filtered = runCatching { runner.filter(filterReqs) }.getOrDefault(emptyMap())
                    val items = LinkedHashMap<String, ExportItem>()
                    for ((file, _) in byFile) {
                        val uri = fileUris[file] ?: continue
                        val data = filtered[file]
                        items[file] = ExportItem(file) { data ?: FolderScanner.read(ctx, uri) }
                    }
                    for (row in chosen) {
                        for (dep in row.config.dependencies) {
                            if (items.containsKey(dep)) continue
                            val uri = fileUris[dep] ?: continue
                            items[dep] = ExportItem(dep) { FolderScanner.read(ctx, uri) }
                        }
                    }
                    SafConfigExporter(ctx).export(items.values.toList(), dest)
                }
                val where = FolderScanner.label(dest)
                val msg = if (report.failed.isEmpty()) {
                    "Saved ${chosen.size} config(s) as ${report.written} file(s) to $where"
                } else {
                    "Saved ${report.written} file(s) to $where, ${report.failed.size} failed"
                }
                _state.update { it.copy(message = msg) }
            } catch (e: Exception) {
                _state.update { it.copy(message = "Save failed: ${e.message}") }
            } finally {
                _state.update { it.copy(saving = false, phase = null) }
            }
        }
    }

    private fun systemDns(): List<String> = runCatching {
        val cm = getApplication<Application>().getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.activeNetwork ?: return emptyList()
        cm.getLinkProperties(net)?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
    }.getOrDefault(emptyList())

    override fun onCleared() {
        runner.stop()
        super.onCleared()
    }
}
