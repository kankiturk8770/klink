package com.gozar.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat

class MainActivity : ComponentActivity() {
    private val vm: GozarViewModel by viewModels()

    private val vpnPrepare = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == RESULT_OK) {
            GozarVpnService.start(this)
        } else {
            vm.showToast(getString(R.string.vpn_permission_needed))
        }
    }

    private val qrScan = registerForActivityResult(QrScanActivity.Contract()) { contents ->
        contents?.let { onScanned(it) }
    }

    private val notifPerm = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        maybeRequestNotifications()
        setContent {
            val state by vm.state.collectAsState()
            GozarApp(
                vm = vm,
                onToggleConnect = { toggleConnect(state) },
                onScanQr = { qrScan.launch(Unit) },
            )
        }
    }

    private fun toggleConnect(state: VpnState) {
        if (state == VpnState.CONNECTED || state == VpnState.CONNECTING) {
            GozarVpnService.stop(this)
            return
        }
        if (vm.settings.value.activeProfileId == null && vm.profiles.value.isEmpty()) {
            vm.showToast(getString(R.string.select_profile_first))
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPrepare.launch(prepare) else GozarVpnService.start(this)
    }

    private fun onScanned(contents: String) {
        vm.addLink(contents) { ok, desc ->
            vm.showToast(if (ok) getString(R.string.profile_added) else getString(R.string.invalid_link))
        }
    }

    private fun maybeRequestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
