package com.arad.vpn_tester.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.arad.vpn_tester.R

const val APP_TITLE = "🍒 Albalu 🍒"
const val CHANNEL_HANDLE = "@albaluv2"
const val CHANNEL_LINK = "t.me/albaluv2"
const val CHANNEL_URL = "https://t.me/albaluv2"

@Composable
fun rememberOpenChannel(): () -> Unit {
    val uri = LocalUriHandler.current
    return { runCatching { uri.openUri(CHANNEL_URL) } }
}

@Composable
fun ChannelButton() {
    val open = rememberOpenChannel()
    TextButton(onClick = open) {
        Icon(painterResource(R.drawable.ic_telegram), contentDescription = null, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text(CHANNEL_HANDLE)
    }
}

@Composable
fun ChannelFooter() {
    val open = rememberOpenChannel()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = open)
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "$APP_TITLE  ·  $CHANNEL_LINK  ·  $CHANNEL_HANDLE",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}
