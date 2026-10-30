package com.arad.vpn_tester.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.arad.vpn_tester.data.Settings
import kotlin.math.roundToInt

@Composable
fun SettingsScreen(vm: TesterViewModel, padding: PaddingValues) {
    val s by vm.settings.collectAsStateWithLifecycle()
    val steps = Settings.CONCURRENCY_STEPS
    val stepIndex = steps.indexOfFirst { it >= s.concurrency }.let { if (it < 0) steps.lastIndex else it }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Section("Test URLs") {
            Text(
                "Every config requests both URLs at the same time. The first HTTP 204 answer counts as the ping.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = s.url1,
                onValueChange = { vm.updateSettings(s.copy(url1 = it)) },
                label = { Text("URL 1") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = s.url2,
                onValueChange = { vm.updateSettings(s.copy(url2 = it)) },
                label = { Text("URL 2") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            TextButton(onClick = {
                vm.updateSettings(s.copy(url1 = Settings.DEFAULT_URL_1, url2 = Settings.DEFAULT_URL_2))
            }) { Text("Reset to defaults") }
        }

        Section("Timeout: ${"%.1f".format(s.timeoutMs / 1000.0)} s") {
            Text(
                "How long one config gets before it counts as failed.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Slider(
                value = s.timeoutMs.toFloat(),
                onValueChange = { vm.updateSettings(s.copy(timeoutMs = ((it / 500f).roundToInt() * 500).coerceIn(2000, 20000))) },
                valueRange = 2000f..20000f,
                steps = 35,
            )
        }

        Section("Parallel tests: ${s.concurrency}") {
            Text(
                "How many configs are tested at once. Higher is faster, but very high values can overload a weak connection.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Slider(
                value = stepIndex.toFloat(),
                onValueChange = { vm.updateSettings(s.copy(concurrency = steps[it.roundToInt().coerceIn(0, steps.lastIndex)])) },
                valueRange = 0f..steps.lastIndex.toFloat(),
                steps = steps.size - 2,
            )
        }

        Section("Subscriptions") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Fetch subscription links", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Download http(s) subscription URLs found in the text and test their configs.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = s.fetchSubscriptions, onCheckedChange = { vm.updateSettings(s.copy(fetchSubscriptions = it)) })
            }
        }

        Section("Folder scan: ${s.folderConcurrency} parallel tests") {
            Text(
                "How many config files are tested at once on the Folder page.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Slider(
                value = s.folderConcurrency.toFloat(),
                onValueChange = { vm.updateSettings(s.copy(folderConcurrency = it.roundToInt().coerceIn(1, 64))) },
                valueRange = 1f..64f,
                steps = 62,
            )
            TimeoutSlider("Overall timeout", s.folderOverallMs, 5000, 60000) { vm.updateSettings(s.copy(folderOverallMs = it)) }
            TimeoutSlider("DNS timeout", s.folderDnsMs, 1000, 15000) { vm.updateSettings(s.copy(folderDnsMs = it)) }
            TimeoutSlider("Connect timeout", s.folderConnectMs, 1000, 20000) { vm.updateSettings(s.copy(folderConnectMs = it)) }
            TimeoutSlider("Handshake timeout", s.folderHandshakeMs, 2000, 30000) { vm.updateSettings(s.copy(folderHandshakeMs = it)) }
            TimeoutSlider("Authentication timeout", s.folderAuthMs, 2000, 30000) { vm.updateSettings(s.copy(folderAuthMs = it)) }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Data probe", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "After a successful handshake, send one test request through the tunnel (inside the app only).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = s.folderDataProbe, onCheckedChange = { vm.updateSettings(s.copy(folderDataProbe = it)) })
            }
        }

        Section("Supported links") {
            Text(
                "VLESS, VMess, Trojan, Trojan-Go, Shadowsocks (incl. 2022, obfs, v2ray-plugin, shadow-tls, kcptun), ShadowsocksR, " +
                    "SOCKS4/4a/5, HTTP/HTTPS, Hysteria, Hysteria2 (+Realm), TUIC, Juicity, AnyTLS, NaiveProxy (H2/QUIC), " +
                    "Brook, SSH, Snell v1–v3, Mieru, MASQUE, TrustTunnel (tt://), ShadowTLS, MTProto (tg://), v2rayN inner links.\n\n" +
                    "Transports: TCP, TLS, REALITY, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP, mKCP, QUIC-based protocols.\n\n" +
                    "Engines: Xray-core, mihomo, juicity, brook and native MTProto / SOCKS4 testers.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TimeoutSlider(label: String, value: Int, min: Int, max: Int, onChange: (Int) -> Unit) {
    Text("$label: ${"%.1f".format(value / 1000.0)} s", style = MaterialTheme.typography.bodyMedium)
    Slider(
        value = value.toFloat().coerceIn(min.toFloat(), max.toFloat()),
        onValueChange = { onChange(((it / 500f).roundToInt() * 500).coerceIn(min, max)) },
        valueRange = min.toFloat()..max.toFloat(),
        steps = ((max - min) / 500) - 1,
    )
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            content()
        }
    }
}
