package com.gozar.app

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.delay

private val Bg = Color(0xFF0B1020)
private val Surface1 = Color(0xFF151C30)
private val Surface2 = Color(0xFF1E2740)
private val Accent = Color(0xFF4F8CFF)
private val Accent2 = Color(0xFF22D3A6)
private val Danger = Color(0xFFFF6B6B)
private val TextHi = Color(0xFFEAF0FF)
private val TextLo = Color(0xFF8A93AD)

private fun gozarColors() = darkColorScheme(
    primary = Accent, secondary = Accent2, background = Bg, surface = Surface1,
    onPrimary = Color.White, onBackground = TextHi, onSurface = TextHi,
)

@Composable
fun GozarApp(vm: GozarViewModel, onToggleConnect: () -> Unit, onScanQr: () -> Unit) {
    MaterialTheme(colorScheme = gozarColors()) {
        val ctx = LocalContext.current
        val toast by vm.toast.collectAsState()
        val snackbar = remember { SnackbarHostState() }
        LaunchedEffect(toast) {
            toast?.let { snackbar.showSnackbar(it); vm.toastShown() }
        }
        var tab by remember { mutableStateOf(0) }
        Scaffold(
            containerColor = Bg,
            snackbarHost = { SnackbarHost(snackbar) },
            bottomBar = { GozarNav(tab) { tab = it } },
        ) { pad ->
            Box(Modifier.padding(pad).fillMaxSize()) {
                when (tab) {
                    0 -> HomeScreen(vm, onToggleConnect)
                    1 -> ProfilesScreen(vm, onScanQr)
                    2 -> SettingsScreen(vm)
                    else -> LogsScreen(vm)
                }
            }
        }
    }
}

@Composable
private fun GozarNav(selected: Int, onSelect: (Int) -> Unit) {
    NavigationBar(containerColor = Surface1) {
        val items = listOf(
            Triple(0, Icons.Filled.Home, R.string.tab_home),
            Triple(1, Icons.Filled.Dns, R.string.tab_profiles),
            Triple(2, Icons.Filled.Tune, R.string.tab_settings),
            Triple(3, Icons.Filled.Article, R.string.tab_logs),
        )
        items.forEach { (i, icon, label) ->
            NavigationBarItem(
                selected = selected == i,
                onClick = { onSelect(i) },
                icon = { Icon(icon, null) },
                label = { Text(stringResource(label)) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Accent, selectedTextColor = Accent,
                    indicatorColor = Surface2, unselectedIconColor = TextLo, unselectedTextColor = TextLo,
                ),
            )
        }
    }
}

// ---------------------------------------------------------------- Home
@Composable
private fun HomeScreen(vm: GozarViewModel, onToggle: () -> Unit) {
    val state by vm.state.collectAsState()
    val stats by vm.stats.collectAsState()
    val profiles by vm.profiles.collectAsState()
    val settings by vm.settings.collectAsState()
    val err by vm.lastError.collectAsState()
    val active = profiles.firstOrNull { it.id == settings.activeProfileId } ?: profiles.firstOrNull()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.app_name), color = TextHi, fontSize = 26.sp)
        Text(stringResource(R.string.tagline), color = TextLo, fontSize = 13.sp)
        Spacer(Modifier.height(28.dp))

        ConnectButton(state, onToggle)
        Spacer(Modifier.height(16.dp))
        val label = when (state) {
            VpnState.CONNECTED -> stringResource(R.string.connected)
            VpnState.CONNECTING -> stringResource(R.string.connecting)
            VpnState.ERROR -> stringResource(R.string.state_error)
            else -> stringResource(R.string.disconnected)
        }
        Text(label, color = if (state == VpnState.ERROR) Danger else TextHi, fontSize = 18.sp)
        if (state == VpnState.ERROR && err.isNotEmpty()) {
            Text(err, color = Danger, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
        }
        active?.let {
            Spacer(Modifier.height(8.dp))
            Surface(color = Surface1, shape = RoundedCornerShape(12.dp)) {
                Text(
                    "${it.remark}  ·  ${it.protocol.ifEmpty { "?" }}",
                    color = TextLo, fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        ModeChip(settings.mode)

        Spacer(Modifier.height(26.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(Modifier.weight(1f), stringResource(R.string.stat_down), humanBytes(stats.bytesDn), Accent)
            StatCard(Modifier.weight(1f), stringResource(R.string.stat_up), humanBytes(stats.bytesUp), Accent2)
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(Modifier.weight(1f), stringResource(R.string.stat_conns), "${stats.active}/${stats.total}", TextHi)
            StatCard(Modifier.weight(1f), stringResource(R.string.stat_fake), "${stats.fakeSent}", TextHi)
        }
    }
}

@Composable
private fun ConnectButton(state: VpnState, onToggle: () -> Unit) {
    val on = state == VpnState.CONNECTED
    val connecting = state == VpnState.CONNECTING
    val ring by animateColorAsState(if (on) Accent2 else if (state == VpnState.ERROR) Danger else Accent, label = "ring")
    Box(
        Modifier.size(180.dp).clip(CircleShape)
            .background(Brush.radialGradient(listOf(Surface2, Surface1)))
            .border(4.dp, ring, CircleShape)
            .clickable { onToggle() },
        contentAlignment = Alignment.Center,
    ) {
        if (connecting) {
            CircularProgressIndicator(color = ring, strokeWidth = 4.dp, modifier = Modifier.size(64.dp))
        } else {
            Icon(Icons.Filled.Power, null, tint = ring, modifier = Modifier.size(72.dp))
        }
    }
}

@Composable
private fun ModeChip(mode: SpoofMode) {
    Surface(color = Surface2, shape = RoundedCornerShape(20.dp)) {
        Row(
            Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(if (mode.isRoot) Icons.Filled.Shield else Icons.Filled.Bolt, null, tint = Accent, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(mode.labelRes), color = TextHi, fontSize = 12.sp)
        }
    }
}

@Composable
private fun StatCard(modifier: Modifier, label: String, value: String, accent: Color) {
    Surface(modifier, color = Surface1, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text(label, color = TextLo, fontSize = 12.sp)
            Spacer(Modifier.height(6.dp))
            Text(value, color = accent, fontSize = 20.sp)
        }
    }
}

// ---------------------------------------------------------------- Profiles
@Composable
private fun ProfilesScreen(vm: GozarViewModel, onScanQr: () -> Unit) {
    val profiles by vm.profiles.collectAsState()
    val settings by vm.settings.collectAsState()
    val latency by vm.latency.collectAsState()
    var showAdd by remember { mutableStateOf(false) }

    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            SectionTitle(stringResource(R.string.tab_profiles))
            Spacer(Modifier.height(8.dp))
            if (profiles.isEmpty()) {
                Text(stringResource(R.string.no_profiles), color = TextLo, modifier = Modifier.padding(16.dp))
            }
            Column(Modifier.verticalScroll(rememberScrollState())) {
                profiles.forEach { p ->
                    ProfileRow(
                        p, active = p.id == settings.activeProfileId, latency = latency[p.id],
                        onActivate = { vm.setActive(p.id) },
                        onDelete = { vm.delete(p.id) },
                        onTest = { vm.testLatency() },
                    )
                    Spacer(Modifier.height(10.dp))
                }
                Spacer(Modifier.height(72.dp))
            }
        }
        FloatingActionButton(
            onClick = { showAdd = true },
            containerColor = Accent,
            modifier = Modifier.align(Alignment.BottomEnd).padding(20.dp),
        ) { Icon(Icons.Filled.Add, null, tint = Color.White) }
    }

    if (showAdd) AddProfileDialog(vm, onScanQr, onDismiss = { showAdd = false })
}

@Composable
private fun ProfileRow(
    p: Profile, active: Boolean, latency: String?,
    onActivate: () -> Unit, onDelete: () -> Unit, onTest: () -> Unit,
) {
    Surface(
        color = if (active) Surface2 else Surface1,
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().then(
            if (active) Modifier.border(1.dp, Accent, RoundedCornerShape(16.dp)) else Modifier
        ).clickable { onActivate() },
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (active) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
                null, tint = if (active) Accent2 else TextLo, modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(p.remark, color = TextHi, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${p.protocol.ifEmpty { "?" }} · ${p.host}:${p.port}" + (latency?.let { "  ·  $it" } ?: ""),
                    color = TextLo, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            IconButton(onClick = onTest) { Icon(Icons.Filled.Speed, null, tint = Accent) }
            IconButton(onClick = onDelete) { Icon(Icons.Filled.Delete, null, tint = Danger) }
        }
    }
}

@Composable
private fun AddProfileDialog(vm: GozarViewModel, onScanQr: () -> Unit, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Surface1,
        title = { Text(stringResource(R.string.add_profile), color = TextHi) },
        text = {
            Column {
                OutlinedTextField(
                    value = text, onValueChange = { text = it },
                    placeholder = { Text(stringResource(R.string.paste_link_hint), color = TextLo, fontSize = 12.sp) },
                    minLines = 3, maxLines = 6,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AssistChip(onClick = {
                        clipboard.getText()?.text?.let { text = it.toString() }
                    }, label = { Text(stringResource(R.string.import_clipboard), fontSize = 11.sp) },
                        leadingIcon = { Icon(Icons.Filled.ContentPaste, null, Modifier.size(16.dp)) })
                    AssistChip(onClick = { onDismiss(); onScanQr() },
                        label = { Text(stringResource(R.string.import_qr), fontSize = 11.sp) },
                        leadingIcon = { Icon(Icons.Filled.QrCodeScanner, null, Modifier.size(16.dp)) })
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val body = text.trim()
                if (body.isEmpty()) { onDismiss(); return@TextButton }
                if (body.lines().size > 1 || !body.contains("://")) {
                    vm.addSubscription(body) { n, errMsg ->
                        vm.showToast(if (n > 0) "+$n" else (errMsg ?: "0"))
                    }
                } else {
                    vm.addLink(body) { ok, _ -> vm.showToast(if (ok) "ok" else "invalid") }
                }
                onDismiss()
            }) { Text(stringResource(R.string.save), color = Accent) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel), color = TextLo) } },
    )
}

// ---------------------------------------------------------------- Settings
@Composable
private fun SettingsScreen(vm: GozarViewModel) {
    val s by vm.settings.collectAsState()
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        SectionTitle(stringResource(R.string.section_spoof))
        ToggleRow(stringResource(R.string.spoof_enabled), stringResource(R.string.spoof_enabled_sub), s.spoofEnabled) {
            vm.update { it.copy(spoofEnabled = it.spoofEnabled.not()) }
        }
        ModeSelector(s.mode) { m -> vm.update { it.copy(mode = m) } }
        if (s.mode.isRoot) InfoNote(stringResource(R.string.root_required))

        Spacer(Modifier.height(16.dp))
        SectionTitle(stringResource(R.string.section_advanced))
        TextFieldRow(stringResource(R.string.fake_sni), s.fakeSni, hint = stringResource(R.string.fake_sni_hint)) { v ->
            vm.update { it.copy(fakeSni = v) }
        }
        DropdownRow(stringResource(R.string.utls), s.utls, utlsOptions) { v -> vm.update { it.copy(utls = v) } }
        ToggleRow(stringResource(R.string.enable_fragment), null, s.enableFragment) {
            vm.update { it.copy(enableFragment = it.enableFragment.not()) }
        }
        NumberRow(stringResource(R.string.sni_chunk), s.sniChunk) { v -> vm.update { it.copy(sniChunk = v) } }
        NumberRow(stringResource(R.string.fragment_delay), s.fragmentDelayMs) { v -> vm.update { it.copy(fragmentDelayMs = v) } }
        NumberRow(stringResource(R.string.fake_repeat), s.fakeRepeat) { v -> vm.update { it.copy(fakeRepeat = v) } }
        NumberRow(stringResource(R.string.fake_delay), s.fakeDelayMs) { v -> vm.update { it.copy(fakeDelayMs = v) } }
        NumberRow(stringResource(R.string.ack_timeout), s.ackTimeoutMs) { v -> vm.update { it.copy(ackTimeoutMs = v) } }

        if (!s.mode.isRoot) {
            Spacer(Modifier.height(4.dp))
            NumberRow(stringResource(R.string.fake_ttl), s.fakeTtl) { v -> vm.update { it.copy(fakeTtl = v) } }
            NumberRow(stringResource(R.string.fake_hold), s.fakeHoldMs) { v -> vm.update { it.copy(fakeHoldMs = v) } }
            ToggleRow(stringResource(R.string.tls_record_split), null, s.tlsRecordSplit) {
                vm.update { it.copy(tlsRecordSplit = it.tlsRecordSplit.not()) }
            }
            ToggleRow(stringResource(R.string.disorder), null, s.disorder) {
                vm.update { it.copy(disorder = it.disorder.not()) }
            }
            if (s.disorder) NumberRow(stringResource(R.string.disorder_ttl), s.disorderTtl) { v -> vm.update { it.copy(disorderTtl = v) } }
            ToggleRow(stringResource(R.string.oob), null, s.oob) { vm.update { it.copy(oob = it.oob.not()) } }
        }
        NumberRow(stringResource(R.string.connect_timeout), s.connectTimeoutMs) { v -> vm.update { it.copy(connectTimeoutMs = v) } }

        Spacer(Modifier.height(16.dp))
        SectionTitle(stringResource(R.string.section_network))
        TextFieldRow(stringResource(R.string.dns), s.dns) { v -> vm.update { it.copy(dns = v) } }
        DropdownRow(stringResource(R.string.log_level), s.logLevel, logLevels) { v -> vm.update { it.copy(logLevel = v) } }
        ToggleRow(stringResource(R.string.sniffing), null, s.sniffing) { vm.update { it.copy(sniffing = it.sniffing.not()) } }
        ToggleRow(stringResource(R.string.bypass_lan), null, s.bypassLan) { vm.update { it.copy(bypassLan = it.bypassLan.not()) } }

        Spacer(Modifier.height(16.dp))
        SectionTitle(stringResource(R.string.section_app))
        ToggleRow(stringResource(R.string.auto_connect_boot), null, s.autoConnectOnBoot) {
            vm.update { it.copy(autoConnectOnBoot = it.autoConnectOnBoot.not()) }
        }
        Spacer(Modifier.height(40.dp))
    }
}

private val utlsOptions = listOf("chrome", "firefox", "edge", "safari", "ios", "qq", "360browser", "none")
private val logLevels = listOf("debug", "info", "warning", "error", "none")

@Composable
private fun ModeSelector(mode: SpoofMode, onPick: (SpoofMode) -> Unit) {
    Column(Modifier.padding(vertical = 8.dp)) {
        Text(stringResource(R.string.mode), color = TextLo, fontSize = 12.sp)
        Spacer(Modifier.height(6.dp))
        SpoofMode.entries.forEach { m ->
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                    .background(if (m == mode) Surface2 else Color.Transparent)
                    .clickable { onPick(m) }.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = m == mode, onClick = { onPick(m) },
                    colors = RadioButtonDefaults.colors(selectedColor = Accent, unselectedColor = TextLo))
                Text(stringResource(m.labelRes), color = TextHi, fontSize = 14.sp)
            }
        }
    }
}

// ---------------------------------------------------------------- Logs
@Composable
private fun LogsScreen(vm: GozarViewModel) {
    val logs by vm.logs.collectAsState()
    val clipboard = LocalClipboardManager.current
    LaunchedEffect(Unit) {
        while (true) { vm.refreshLogs(); delay(1500) }
    }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle(stringResource(R.string.tab_logs))
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { clipboard.setText(androidx.compose.ui.text.AnnotatedString(logs)) }) {
                Icon(Icons.Filled.ContentCopy, null, tint = Accent)
            }
        }
        Spacer(Modifier.height(8.dp))
        Surface(color = Color(0xFF070B16), shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxSize()) {
            Text(
                logs.ifEmpty { stringResource(R.string.logs_empty) },
                color = Color(0xFFBFE3C6), fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                modifier = Modifier.verticalScroll(rememberScrollState()).padding(12.dp),
            )
        }
    }
}

// ---------------------------------------------------------------- shared rows
@Composable
private fun SectionTitle(t: String) {
    Text(t, color = Accent, fontSize = 14.sp, modifier = Modifier.padding(vertical = 6.dp))
}

@Composable
private fun ToggleRow(title: String, sub: String?, value: Boolean, onToggle: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable { onToggle() }.padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, color = TextHi, fontSize = 15.sp)
            sub?.let { Text(it, color = TextLo, fontSize = 11.sp) }
        }
        Switch(checked = value, onCheckedChange = { onToggle() },
            colors = SwitchDefaults.colors(checkedTrackColor = Accent, checkedThumbColor = Color.White))
    }
}

@Composable
private fun NumberRow(title: String, value: Int, onChange: (Int) -> Unit) {
    var text by remember(value) { mutableStateOf(value.toString()) }
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(title, color = TextHi, fontSize = 14.sp, modifier = Modifier.weight(1f))
        OutlinedTextField(
            value = text,
            onValueChange = { t -> text = t.filter { it.isDigit() }; text.toIntOrNull()?.let(onChange) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.width(110.dp),
        )
    }
}

@Composable
private fun TextFieldRow(title: String, value: String, hint: String? = null, onChange: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text(title, color = TextHi, fontSize = 14.sp)
        OutlinedTextField(
            value = value, onValueChange = onChange, singleLine = true,
            placeholder = hint?.let { { Text(it, color = TextLo, fontSize = 11.sp) } },
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun DropdownRow(title: String, value: String, options: List<String>, onPick: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(title, color = TextHi, fontSize = 14.sp, modifier = Modifier.weight(1f))
        Box {
            AssistChip(onClick = { expanded = true }, label = { Text(value) },
                trailingIcon = { Icon(Icons.Filled.ArrowDropDown, null) })
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                options.forEach { o ->
                    DropdownMenuItem(text = { Text(o) }, onClick = { onPick(o); expanded = false })
                }
            }
        }
    }
}

@Composable
private fun InfoNote(text: String) {
    Surface(color = Surface2, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Info, null, tint = Accent, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(8.dp))
            Text(text, color = TextLo, fontSize = 12.sp)
        }
    }
}

private fun humanBytes(n: Long): String {
    if (n < 1024) return "$n B"
    val kb = n / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    val mb = kb / 1024.0
    if (mb < 1024) return "%.1f MB".format(mb)
    return "%.2f GB".format(mb / 1024.0)
}
