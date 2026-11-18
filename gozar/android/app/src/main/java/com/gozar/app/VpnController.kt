package com.gozar.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Process-wide tunnel state shared between the VpnService and the UI. */
object VpnController {
    private val _state = MutableStateFlow(VpnState.DISCONNECTED)
    val state: StateFlow<VpnState> = _state

    private val _stats = MutableStateFlow(Stats())
    val stats: StateFlow<Stats> = _stats

    private val _lastError = MutableStateFlow("")
    val lastError: StateFlow<String> = _lastError

    fun setState(s: VpnState) { _state.value = s }
    fun setStats(s: Stats) { _stats.value = s }
    fun setError(msg: String) { _lastError.value = msg; _state.value = VpnState.ERROR }

    const val ACTION_START = "com.gozar.app.START"
    const val ACTION_STOP = "com.gozar.app.STOP"
}
