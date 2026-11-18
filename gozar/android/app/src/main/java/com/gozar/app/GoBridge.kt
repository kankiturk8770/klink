package com.gozar.app

import com.google.gson.Gson
import com.gozar.core.mobile.Mobile
import com.gozar.core.mobile.LogCallback
import com.gozar.core.mobile.VpnProtect

/**
 * Thin, single source of truth over the gomobile-bound Go core
 * (com.gozar.core.mobile.Mobile). gomobile lowercases the first letter of each
 * exported Go function, so Go `Start` becomes Java `start`, etc.
 */
object GoBridge {
    private val gson = Gson()

    fun setLogCallback(cb: ((String) -> Unit)?) {
        if (cb == null) {
            Mobile.setLogCallback(null)
        } else {
            Mobile.setLogCallback(object : LogCallback {
                override fun onLog(line: String) = cb(line)
            })
        }
    }

    fun setProtect(protect: ((Int) -> Boolean)?) {
        if (protect == null) {
            Mobile.setProtect(null)
        } else {
            Mobile.setProtect(object : VpnProtect {
                override fun protect(fd: Long): Boolean = protect(fd.toInt())
            })
        }
    }

    /** Validate a single link; returns a human description or throws. */
    fun validateLink(raw: String): String = Mobile.validateLink(raw)

    /** Resolve the server endpoint for a link (used by the root-helper flow). */
    fun serverInfo(raw: String): ServerInfo =
        gson.fromJson(Mobile.serverInfoJSON(raw), ServerInfo::class.java)

    /** @return the local SOCKS port. Throws on failure. tunFd < 0 = SOCKS only. */
    fun start(settings: EngineSettings, tunFd: Int, mtu: Int): Int {
        val json = gson.toJson(settings)
        return Mobile.start(json, tunFd.toLong(), mtu.toLong()).toInt()
    }

    fun stop() = Mobile.stop()
    fun isRunning(): Boolean = Mobile.isRunning()
    fun socksPort(): Int = Mobile.socksPort().toInt()
    fun logs(): String = Mobile.logs()

    fun stats(): Stats = runCatching {
        gson.fromJson(Mobile.statsJSON(), Stats::class.java)
    }.getOrDefault(Stats())

    /** @return latency in ms. Throws on failure. */
    fun urlTest(url: String, timeoutMs: Int): Long = Mobile.urlTest(url, timeoutMs.toLong())
}

/** Maps the UI Settings + active profile link into the engine JSON shape.
 *  In root mode the privileged spoof proxy runs in the external helper, so the
 *  in-engine spoof is disabled and Xray is pointed at the helper's listener via
 *  the dial-override (helperHost/helperPort). */
object SettingsMapper {
    fun toEngine(
        s: Settings,
        activeLink: String,
        socksPort: Int,
        helperHost: String = "",
        helperPort: Int = 0,
    ): EngineSettings {
        val rootExternal = s.mode.isRoot && helperPort != 0
        return EngineSettings(
            links = listOf(activeLink),
            spoof = engineSpoof(s, enabled = s.spoofEnabled && !rootExternal),
            socksPort = socksPort,
            dns = s.dns,
            logLevel = s.logLevel,
            enableSniffing = s.sniffing,
            dialOverrideHost = if (rootExternal) helperHost else "",
            dialOverridePort = if (rootExternal) helperPort else 0,
        )
    }

    private fun engineSpoof(s: Settings, enabled: Boolean) = EngineSpoof(
            enabled = enabled,
            fakeSni = s.fakeSni,
            utls = s.utls,
            mode = s.mode.wire,
            fakeRepeat = s.fakeRepeat,
            fakeDelayMs = s.fakeDelayMs,
            ackTimeoutMs = s.ackTimeoutMs,
            enableFragment = s.enableFragment,
            fragmentDelayMs = s.fragmentDelayMs,
            sniChunk = s.sniChunk,
            fakeTtl = s.fakeTtl,
            fakeHoldMs = s.fakeHoldMs,
            tlsRecordSplit = s.tlsRecordSplit,
            disorder = s.disorder,
            disorderTtl = s.disorderTtl,
            oob = s.oob,
            connectTimeoutMs = s.connectTimeoutMs,
    )
}
