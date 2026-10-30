package com.arad.vpn_tester.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.arad.vpn_tester.parse.Kind
import com.arad.vpn_tester.ui.theme.DelayFastDark
import com.arad.vpn_tester.ui.theme.DelayFastLight
import com.arad.vpn_tester.ui.theme.DelayMidDark
import com.arad.vpn_tester.ui.theme.DelayMidLight
import com.arad.vpn_tester.ui.theme.DelaySlowDark
import com.arad.vpn_tester.ui.theme.DelaySlowLight

@Composable
fun TestScreen(vm: TesterViewModel, padding: PaddingValues) {
    val state by vm.state.collectAsStateWithLifecycle()
    var expanded by remember { mutableStateOf(setOf<Long>()) }
    val visible = remember(state.entries, state.filter) {
        when (state.filter) {
            Filter.ALL -> state.entries
            Filter.WORKING -> state.entries.filter { it.status == Status.OK }.sortedBy { it.delay }
            Filter.FAILED -> state.entries.filter { it.status == Status.FAIL || it.status == Status.SKIPPED }
        }
    }
    val failedCount = state.entries.count { it.status == Status.FAIL || it.status == Status.SKIPPED }

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
        item(key = "input") { InputCard(vm, state.running) }
        if (state.vpnActive) {
            item(key = "vpn") { VpnWarning() }
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
                    Button(onClick = vm::run, modifier = Modifier.weight(1f).height(52.dp)) {
                        Icon(painterResource(R.drawable.ic_play), contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Run test")
                    }
                }
                FilledTonalButton(
                    onClick = vm::copyActive,
                    enabled = state.working > 0,
                    modifier = Modifier.weight(1f).height(52.dp),
                ) {
                    Icon(painterResource(R.drawable.ic_copy), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Copy active (${state.working})", maxLines = 1)
                }
            }
        }
        if (state.total > 0 || state.phase != null) {
            item(key = "progress") { ProgressCard(state) }
        }
        if (state.entries.isNotEmpty()) {
            item(key = "filters") {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = state.filter == Filter.ALL,
                        onClick = { vm.setFilter(Filter.ALL) },
                        label = { Text("All ${state.total}") },
                    )
                    FilterChip(
                        selected = state.filter == Filter.WORKING,
                        onClick = { vm.setFilter(Filter.WORKING) },
                        label = { Text("Working ${state.working}") },
                    )
                    FilterChip(
                        selected = state.filter == Filter.FAILED,
                        onClick = { vm.setFilter(Filter.FAILED) },
                        label = { Text("Failed $failedCount") },
                    )
                }
            }
        }
        items(visible, key = { it.id }) { e ->
            EntryRow(
                entry = e,
                running = state.running,
                expanded = e.id in expanded,
                onClick = { expanded = if (e.id in expanded) expanded - e.id else expanded + e.id },
                onCopy = { vm.copyOne(e.link) },
            )
        }
    }
}

@Composable
private fun InputCard(vm: TesterViewModel, running: Boolean) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp)) {
            OutlinedTextField(
                state = vm.input,
                modifier = Modifier.fillMaxWidth().height(220.dp),
                enabled = !running,
                lineLimits = TextFieldLineLimits.MultiLine(),
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                placeholder = {
                    Text(
                        "Paste configs here: vless://, vmess://, trojan://, ss://, hy2://, tuic://, naive+https://, tg://proxy… " +
                            "Subscription links and base64 blobs work too.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                },
            )
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) {
                TextButton(onClick = vm::pasteFromClipboard, enabled = !running) {
                    Icon(painterResource(R.drawable.ic_paste), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Paste")
                }
                TextButton(onClick = vm::clear, enabled = !running) {
                    Icon(painterResource(R.drawable.ic_clear), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Clear")
                }
                Spacer(Modifier.weight(1f))
                Text(
                    "${vm.input.text.let { t -> if (t.isEmpty()) 0 else t.count { it == '\n' } + 1 }} lines",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun VpnWarning() {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
        Text(
            "A VPN is active on this phone, so tests go through it. Turn it off for accurate results.",
            modifier = Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onTertiaryContainer,
        )
    }
}

@Composable
private fun ProgressCard(state: UiState) {
    val testable = (state.total - state.skipped).coerceAtLeast(0)
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (state.phase != null) {
                Text(state.phase, style = MaterialTheme.typography.bodyMedium)
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(
                    progress = { if (testable == 0) 1f else state.tested.toFloat() / testable },
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "${state.tested} / $testable tested",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        "${state.working} working",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = delayColor(1),
                    )
                }
            }
            val notes = buildList {
                if (state.skipped > 0) add("${state.skipped} skipped (tunnel / encrypted)")
                if (state.subscriptions > 0) add("${state.subscriptions} subscription(s), ${state.subscriptionsFailed} failed")
            }
            if (notes.isNotEmpty()) {
                Text(
                    notes.joinToString(" · "),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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

@Composable
private fun EntryRow(entry: Entry, running: Boolean, expanded: Boolean, onClick: () -> Unit, onCopy: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                ) {
                    Text(
                        entry.protocol,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        maxLines = 1,
                    )
                }
                Spacer(Modifier.width(10.dp))
                Text(
                    entry.name,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.width(10.dp))
                StatusLabel(entry, running)
            }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                entry.error?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                entry.engine?.let {
                    Text(
                        "engine: $it",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    entry.link,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 4.dp),
                )
                TextButton(onClick = onCopy) {
                    Icon(painterResource(R.drawable.ic_copy), contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Copy config")
                }
            }
        }
    }
}

@Composable
private fun StatusLabel(entry: Entry, running: Boolean) {
    val style = MaterialTheme.typography.labelLarge
    when (entry.status) {
        Status.OK -> Text("${entry.delay} ms", style = style, fontWeight = FontWeight.SemiBold, color = delayColor(entry.delay))
        Status.FAIL -> Text("failed", style = style, color = MaterialTheme.colorScheme.error)
        Status.PENDING -> Text(if (running) "testing…" else "—", style = style, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Status.SKIPPED -> Text(
            when (entry.kind) {
                Kind.TUNNEL -> "tunnel"
                Kind.ENCRYPTED -> "encrypted"
                else -> "unsupported"
            },
            style = style,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
