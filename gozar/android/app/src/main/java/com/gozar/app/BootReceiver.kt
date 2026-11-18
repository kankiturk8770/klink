package com.gozar.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/** Auto-connects on boot when enabled and VPN consent was already granted. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val settings = Store(context).settingsBlocking()
        if (!settings.autoConnectOnBoot) return
        if (settings.activeProfileId == null) return
        if (VpnService.prepare(context) != null) return // consent not granted; skip
        GozarVpnService.start(context)
    }
}
