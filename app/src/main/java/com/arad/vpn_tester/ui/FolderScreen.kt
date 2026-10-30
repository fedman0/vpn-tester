package com.arad.vpn_tester.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.arad.vpn_tester.R
import com.arad.vpn_tester.core.Stages
import com.arad.vpn_tester.ui.theme.DelayFastDark
import com.arad.vpn_tester.ui.theme.DelayFastLight
import com.arad.vpn_tester.ui.theme.DelayMidDark
import com.arad.vpn_tester.ui.theme.DelayMidLight
import com.arad.vpn_tester.ui.theme.DelaySlowDark
import com.arad.vpn_tester.ui.theme.DelaySlowLight

@Composable
fun FolderScreen(vm: FolderViewModel, padding: PaddingValues) {
    val state by vm.state.collectAsStateWithLifecycle()
    var expanded by remember { mutableStateOf(setOf<Int>()) }
    val pickFolder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { vm.onFolderPicked(it) }
    val pickDest = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { vm.saveSelected(it) }

    val visible = remember(state.rows, state.filter, state.query, state.removeDuplicates) {
        val q = state.query.trim().lowercase()
        state.rows.asSequence()
            .filter { !(state.removeDuplicates && it.config.duplicateOf != 0) }
            .filter {
                when (state.filter) {
                    FolderFilter.ALL -> true
                    FolderFilter.CONNECTABLE -> it.status == RowStatus.CONNECTABLE
                    FolderFilter.FAILED -> it.status == RowStatus.FAILED
                    FolderFilter.INVALID -> it.status == RowStatus.INVALID
                    FolderFilter.UNSUPPORTED -> it.status == RowStatus.UNSUPPORTED
                }
            }
            .filter {
                if (q.isEmpty()) return@filter true
                val c = it.config
                listOf(c.file, c.name, c.protocol, c.format, c.host, c.transport, c.security, c.sni).any { s -> s.lowercase().contains(q) }
            }
            .let { seq -> if (state.filter == FolderFilter.CONNECTABLE) seq.sortedBy { it.result?.latency ?: Long.MAX_VALUE } else seq }
            .toList()
    }
    val selectedCount = state.selected.count { id ->
        state.rows.any { it.config.id == id && !(state.removeDuplicates && it.config.duplicateOf != 0) }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(
            start = 16.dp,
            end = 16.dp,
            top = padding.calculateTopPadding() + 4.dp,
            bottom = padding.calculateBottomPadding() + 16.dp,
        ),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item(key = "folder") {
            FolderCard(
                state = state,
                onPick = { pickFolder.launch(state.folderUri) },
                onSubfolders = vm::setScanSubfolders,
            )
        }
        item(key = "actions") {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                if (state.running) {
                    Button(
                        onClick = vm::stop,
                        modifier = Modifier.weight(1f).height(52.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor = MaterialTheme.colorScheme.onError,
                        ),
                    ) {
                        Icon(painterResource(R.drawable.ic_stop), contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Stop")
                    }
                } else {
                    Button(
                        onClick = vm::scanAndTest,
                        enabled = state.folderUri != null && !state.saving,
                        modifier = Modifier.weight(1f).height(52.dp),
                    ) {
                        Icon(painterResource(R.drawable.ic_play), contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Scan & Test")
                    }
                }
            }
        }
        if (state.running || state.saving || state.rows.isNotEmpty() || state.filesFound > 0) {
            item(key = "progress") { ScanProgressCard(state) }
        }
        if (state.rows.isNotEmpty() && !state.running) {
            item(key = "save") {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(
                        onClick = vm::selectAllConnected,
                        enabled = state.connectable > 0,
                        modifier = Modifier.weight(1f).height(48.dp),
                    ) {
                        Icon(painterResource(R.drawable.ic_done_all), contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Select All Connected", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Button(
                        onClick = { pickDest.launch(null) },
                        enabled = selectedCount > 0 && !state.saving,
                        modifier = Modifier.weight(1f).height(48.dp),
                    ) {
                        Icon(painterResource(R.drawable.ic_save), contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Save Connected ($selectedCount)", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        }
        if (state.rows.isNotEmpty()) {
            item(key = "filters") { FilterBar(state, vm) }
        }
        items(visible, key = { it.config.id }) { row ->
            ScanRowCard(
                row = row,
                running = state.running,
                selected = row.config.id in state.selected,
                expanded = row.config.id in expanded,
                onClick = { expanded = if (row.config.id in expanded) expanded - row.config.id else expanded + row.config.id },
                onToggle = { vm.toggle(row.config.id) },
            )
        }
        if (state.rows.isNotEmpty() && visible.isEmpty()) {
            item(key = "empty") {
                Text(
                    "Nothing matches this filter",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(8.dp),
                )
            }
        }
        item(key = "footer") { ChannelFooter() }
    }
}

@Composable
private fun FolderCard(state: FolderUiState, onPick: () -> Unit, onSubfolders: (Boolean) -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Config folder", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    state.folderLabel ?: "No folder selected",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (state.folderLabel == null) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(10.dp))
                OutlinedButton(onClick = onPick, enabled = !state.running && !state.saving) {
                    Icon(painterResource(R.drawable.ic_folder), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Select Folder")
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Scan subfolders", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                Switch(checked = state.scanSubfolders, onCheckedChange = onSubfolders, enabled = !state.running)
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ScanProgressCard(state: FolderUiState) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            when {
                state.phase != null && state.progress != null -> {
                    Text(state.phase, style = MaterialTheme.typography.bodyMedium)
                    LinearProgressIndicator(progress = { state.progress }, modifier = Modifier.fillMaxWidth())
                }
                state.phase != null -> {
                    Text(state.phase, style = MaterialTheme.typography.bodyMedium)
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
                else -> {
                    LinearProgressIndicator(
                        progress = { if (state.testable == 0) 1f else state.tested.toFloat() / state.testable },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        if (state.running) "Testing ${state.tested} / ${state.testable}" else "Tested ${state.tested} / ${state.testable}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Stat("Files", state.filesFound)
                Stat("Configs", state.configs)
                Stat("Valid", state.valid)
                Stat("Connectable", state.connectable, delayColor(1))
                Stat("Failed", state.failed, MaterialTheme.colorScheme.error)
                Stat("Invalid", state.invalid)
                Stat("Unsupported", state.unsupported)
            }
            val notes = buildList {
                if (state.dependencies > 0) add("${state.dependencies} certificate/key file(s) linked")
                if (state.duplicates > 0) add("${state.duplicates} duplicate(s)")
            }
            if (notes.isNotEmpty()) {
                Text(notes.joinToString(" · "), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: Int, color: Color = MaterialTheme.colorScheme.onSurface) {
    Surface(shape = RoundedCornerShape(10.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh) {
        Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
            Text("$value", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = color)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FilterBar(state: FolderUiState, vm: FolderViewModel) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = state.query,
            onValueChange = vm::setQuery,
            placeholder = { Text("Search file, server, protocol…") },
            leadingIcon = { Icon(painterResource(R.drawable.ic_search), contentDescription = null, modifier = Modifier.size(20.dp)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val total = state.rows.count { !(state.removeDuplicates && it.config.duplicateOf != 0) }
            FilterChip(selected = state.filter == FolderFilter.ALL, onClick = { vm.setFilter(FolderFilter.ALL) }, label = { Text("All $total") })
            FilterChip(selected = state.filter == FolderFilter.CONNECTABLE, onClick = { vm.setFilter(FolderFilter.CONNECTABLE) }, label = { Text("Connectable ${state.connectable}") })
            FilterChip(selected = state.filter == FolderFilter.FAILED, onClick = { vm.setFilter(FolderFilter.FAILED) }, label = { Text("Failed ${state.failed}") })
            FilterChip(selected = state.filter == FolderFilter.INVALID, onClick = { vm.setFilter(FolderFilter.INVALID) }, label = { Text("Invalid ${state.invalid}") })
            FilterChip(selected = state.filter == FolderFilter.UNSUPPORTED, onClick = { vm.setFilter(FolderFilter.UNSUPPORTED) }, label = { Text("Unsupported ${state.unsupported}") })
        }
        if (state.duplicates > 0) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Remove duplicates (${state.duplicates})", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                Switch(checked = state.removeDuplicates, onCheckedChange = vm::setRemoveDuplicates)
            }
        }
    }
}

@Composable
private fun delayColor(ms: Long): Color {
    val dark = isSystemInDarkTheme()
    return when {
        ms < 600 -> if (dark) DelayFastDark else DelayFastLight
        ms < 1500 -> if (dark) DelayMidDark else DelayMidLight
        else -> if (dark) DelaySlowDark else DelaySlowLight
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ScanRowCard(
    row: ScanRow,
    running: Boolean,
    selected: Boolean,
    expanded: Boolean,
    onClick: () -> Unit,
    onToggle: () -> Unit,
) {
    val c = row.config
    val r = row.result
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(start = 4.dp, end = 12.dp, top = 6.dp, bottom = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (row.status == RowStatus.CONNECTABLE) {
                    Checkbox(checked = selected, onCheckedChange = { onToggle() })
                } else {
                    Spacer(Modifier.width(12.dp))
                }
                Column(Modifier.weight(1f)) {
                    Text(
                        if (c.multi) "${c.fileName} #${c.index + 1}" else c.fileName,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (c.name.isNotEmpty() && c.name != c.fileName) {
                        Text(
                            c.name,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                Spacer(Modifier.width(8.dp))
                RowStatusLabel(row, running)
            }
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.padding(start = 12.dp, top = 4.dp),
            ) {
                Tag(c.protocol.ifEmpty { c.format }, MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.colorScheme.onSecondaryContainer)
                if (c.host.isNotEmpty()) {
                    Tag(if (c.port > 0) "${c.host}:${c.port}" else c.host, MaterialTheme.colorScheme.surfaceContainerHighest, MaterialTheme.colorScheme.onSurface)
                }
                val ts = listOf(c.transport, c.security).filter { it.isNotEmpty() }.joinToString(" · ")
                if (ts.isNotEmpty()) Tag(ts, MaterialTheme.colorScheme.surfaceContainerHighest, MaterialTheme.colorScheme.onSurfaceVariant)
                if (c.duplicateOf != 0) Tag("duplicate", MaterialTheme.colorScheme.tertiaryContainer, MaterialTheme.colorScheme.onTertiaryContainer)
            }
            val err = r?.errorMessage ?: c.error
            if (err != null && row.status != RowStatus.CONNECTABLE) {
                Text(
                    err,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (row.status == RowStatus.UNSUPPORTED) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                    maxLines = if (expanded) 6 else 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(start = 12.dp, top = 4.dp),
                )
            }
            if (expanded) {
                Column(Modifier.padding(start = 12.dp, top = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    r?.let { StageRow(it.stages) }
                    Detail("Result", r?.result ?: c.status)
                    Detail("File", c.file)
                    Detail("Format", c.format)
                    if (c.sni.isNotEmpty()) Detail("SNI", c.sni)
                    if (c.username.isNotEmpty()) Detail("User", c.username)
                    r?.address?.let { Detail("Address", it) }
                    r?.engine?.let { Detail("Engine", it) }
                    r?.errorCode?.let { Detail("Error code", it) }
                    r?.note?.let { Detail("Note", it) }
                    if (c.dependencies.isNotEmpty()) Detail("Dependencies", c.dependencies.joinToString(", "))
                    if (c.warnings.isNotEmpty()) Detail("Warnings", c.warnings.joinToString("; "))
                    if (c.duplicateOf != 0) Detail("Duplicate of", "#${c.duplicateOf}")
                }
            }
        }
    }
}

@Composable
private fun StageRow(s: Stages) {
    val items = listOf(
        "Parse" to s.parse,
        "DNS" to s.dns,
        "Transport" to s.transport,
        "Handshake" to s.handshake,
        "Auth" to s.authentication,
        "Data" to s.dataPlane,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        items.forEach { (label, v) ->
            val (mark, color) = when (v) {
                true -> "✓" to delayColor(1)
                false -> "✗" to MaterialTheme.colorScheme.error
                null -> "–" to MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text("$mark $label", style = MaterialTheme.typography.labelSmall, color = color)
        }
    }
}

@Composable
private fun Detail(label: String, value: String) {
    Row {
        Text(
            "$label: ",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun Tag(text: String, bg: Color, fg: Color) {
    Surface(shape = RoundedCornerShape(6.dp), color = bg) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = fg,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun RowStatusLabel(row: ScanRow, running: Boolean) {
    val style = MaterialTheme.typography.labelLarge
    when (row.status) {
        RowStatus.CONNECTABLE -> {
            val ms = row.result?.latency ?: 0
            Column(horizontalAlignment = Alignment.End) {
                Text("$ms ms", style = style, fontWeight = FontWeight.SemiBold, color = delayColor(ms))
                Text(
                    if (row.result?.result == "DataPlaneVerified") "verified" else "connectable",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        RowStatus.FAILED -> Text(
            when (row.result?.result) {
                "DNSFailed" -> "DNS failed"
                "HostUnreachable" -> "unreachable"
                "PortUnreachable" -> "port closed"
                "AuthenticationFailed" -> "auth failed"
                "HandshakeFailed" -> "handshake failed"
                else -> "failed"
            },
            style = style,
            color = MaterialTheme.colorScheme.error,
        )
        RowStatus.INVALID -> Text("invalid", style = style, color = MaterialTheme.colorScheme.error)
        RowStatus.UNSUPPORTED -> Text("unsupported", style = style, color = MaterialTheme.colorScheme.onSurfaceVariant)
        RowStatus.TESTING -> Text("testing…", style = style, color = MaterialTheme.colorScheme.primary)
        RowStatus.PENDING -> Text(if (running) "queued" else "—", style = style, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
