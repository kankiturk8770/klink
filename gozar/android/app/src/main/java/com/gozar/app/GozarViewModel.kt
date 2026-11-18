package com.gozar.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

class GozarViewModel(app: Application) : AndroidViewModel(app) {
    private val store = Store(app)

    val profiles: StateFlow<List<Profile>> =
        store.profiles.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val settings: StateFlow<Settings> =
        store.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())

    val state: StateFlow<VpnState> = VpnController.state
    val stats: StateFlow<Stats> = VpnController.stats
    val lastError: StateFlow<String> = VpnController.lastError

    private val _toast = MutableStateFlow<String?>(null)
    val toast: StateFlow<String?> = _toast
    fun toastShown() { _toast.value = null }

    private val _logs = MutableStateFlow("")
    val logs: StateFlow<String> = _logs

    fun refreshLogs() {
        viewModelScope.launch { _logs.value = runCatching { GoBridge.logs() }.getOrDefault("") }
    }

    /** Adds one share-link; validates via the Go core first. */
    fun addLink(raw: String, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            val trimmed = raw.trim()
            val desc = withContext(Dispatchers.IO) { runCatching { GoBridge.validateLink(trimmed) } }
            desc.onSuccess { d ->
                val info = withContext(Dispatchers.IO) { runCatching { GoBridge.serverInfo(trimmed) }.getOrNull() }
                val p = Profile(
                    id = UUID.randomUUID().toString(),
                    remark = d.substringBefore(" ·").ifBlank { trimmed.take(24) },
                    link = trimmed,
                    protocol = info?.protocol ?: "",
                    host = info?.host ?: "",
                    port = info?.port ?: 0,
                    security = info?.sni?.let { "tls" } ?: "",
                )
                val list = profiles.value + p
                store.saveProfiles(list)
                if (settings.value.activeProfileId == null) setActive(p.id)
                onResult(true, d)
            }.onFailure { onResult(false, it.message ?: "invalid") }
        }
    }

    /** Imports many links from a subscription body (base64 or newline list). */
    fun addSubscription(body: String, onResult: (Int, String?) -> Unit) {
        viewModelScope.launch {
            val lines = body.trim().lines().map { it.trim() }.filter { it.isNotEmpty() }
            // If it's a single blob, let the user paste multiple links; for a base64
            // subscription we add each decoded link by re-validating client side.
            val candidates = if (lines.size > 1) lines else decodeMaybeBase64(body)
            var added = 0
            val newOnes = mutableListOf<Profile>()
            for (c in candidates) {
                val desc = withContext(Dispatchers.IO) { runCatching { GoBridge.validateLink(c) }.getOrNull() }
                    ?: continue
                val info = withContext(Dispatchers.IO) { runCatching { GoBridge.serverInfo(c) }.getOrNull() }
                newOnes += Profile(
                    id = UUID.randomUUID().toString(),
                    remark = desc.substringBefore(" ·").ifBlank { c.take(24) },
                    link = c, protocol = info?.protocol ?: "",
                    host = info?.host ?: "", port = info?.port ?: 0,
                )
                added++
            }
            if (added > 0) {
                val list = profiles.value + newOnes
                store.saveProfiles(list)
                if (settings.value.activeProfileId == null) setActive(newOnes.first().id)
            }
            onResult(added, if (added == 0) "no valid links" else null)
        }
    }

    private fun decodeMaybeBase64(s: String): List<String> {
        val t = s.trim()
        if (t.contains("://")) return listOf(t)
        return runCatching {
            val dec = String(android.util.Base64.decode(t, android.util.Base64.DEFAULT))
            dec.lines().map { it.trim() }.filter { it.isNotEmpty() }
        }.getOrDefault(listOf(t))
    }

    fun delete(id: String) {
        viewModelScope.launch {
            store.saveProfiles(profiles.value.filterNot { it.id == id })
            if (settings.value.activeProfileId == id) {
                store.saveSettings(settings.value.copy(activeProfileId = profiles.value.firstOrNull { it.id != id }?.id))
            }
        }
    }

    fun setActive(id: String) {
        viewModelScope.launch { store.saveSettings(settings.value.copy(activeProfileId = id)) }
    }

    fun update(transform: (Settings) -> Settings) {
        viewModelScope.launch { store.saveSettings(transform(settings.value)) }
    }

    private val _latency = MutableStateFlow<Map<String, String>>(emptyMap())
    val latency: StateFlow<Map<String, String>> = _latency

    fun testLatency() {
        viewModelScope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching { GoBridge.urlTest("https://www.gstatic.com/generate_204", 8000) }
            }
            val active = settings.value.activeProfileId ?: return@launch
            _latency.value = _latency.value.toMutableMap().apply {
                put(active, r.fold({ "${it} ms" }, { "✕" }))
            }
        }
    }

    fun showToast(msg: String) { _toast.value = msg }
}
