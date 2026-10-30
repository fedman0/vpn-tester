package com.arad.vpn_tester

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arad.vpn_tester.ui.FolderScreen
import com.arad.vpn_tester.ui.FolderViewModel
import com.arad.vpn_tester.ui.SettingsScreen
import com.arad.vpn_tester.ui.TestScreen
import com.arad.vpn_tester.ui.TesterViewModel
import com.arad.vpn_tester.ui.theme.VpntesterTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            VpntesterTheme {
                App()
            }
        }
    }
}

enum class Tab(val title: Int, val icon: Int) {
    TEST(R.string.tab_test, R.drawable.ic_bolt),
    FOLDER(R.string.tab_folder, R.drawable.ic_folder),
    SETTINGS(R.string.tab_settings, R.drawable.ic_settings),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(vm: TesterViewModel = viewModel(), folderVm: FolderViewModel = viewModel()) {
    var tab by rememberSaveable { mutableStateOf(Tab.TEST) }
    val snackbar = remember { SnackbarHostState() }
    val state by vm.state.collectAsStateWithLifecycle()
    val folderState by folderVm.state.collectAsStateWithLifecycle()

    LaunchedEffect(state.message) {
        val m = state.message ?: return@LaunchedEffect
        snackbar.showSnackbar(m, duration = SnackbarDuration.Short)
        vm.consumeMessage()
    }
    LaunchedEffect(folderState.message) {
        val m = folderState.message ?: return@LaunchedEffect
        snackbar.showSnackbar(m, duration = SnackbarDuration.Short)
        folderVm.consumeMessage()
    }

    Scaffold(
        topBar = {
            TopAppBar(title = {
                Text(if (tab == Tab.TEST) stringResource(R.string.app_name) else stringResource(tab.title))
            })
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(painterResource(t.icon), contentDescription = null) },
                        label = { Text(stringResource(t.title)) },
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        when (tab) {
            Tab.TEST -> TestScreen(vm, padding)
            Tab.FOLDER -> FolderScreen(folderVm, padding)
            Tab.SETTINGS -> SettingsScreen(vm, padding)
        }
    }
}
