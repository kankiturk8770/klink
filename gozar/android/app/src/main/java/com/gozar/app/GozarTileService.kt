package com.gozar.app

import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Quick Settings tile to toggle the tunnel. */
class GozarTileService : TileService() {
    override fun onStartListening() { refresh() }

    override fun onClick() {
        val connected = VpnController.state.value == VpnState.CONNECTED ||
            VpnController.state.value == VpnState.CONNECTING
        if (connected) {
            GozarVpnService.stop(this)
        } else {
            val prep = VpnService.prepare(this)
            if (prep != null) {
                // Needs user consent; open the app to grant it.
                val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivityAndCollapse(i)
            } else {
                GozarVpnService.start(this)
            }
        }
        refresh()
    }

    private fun refresh() {
        val t = qsTile ?: return
        t.state = when (VpnController.state.value) {
            VpnState.CONNECTED -> Tile.STATE_ACTIVE
            VpnState.CONNECTING -> Tile.STATE_UNAVAILABLE
            else -> Tile.STATE_INACTIVE
        }
        t.updateTile()
    }
}
