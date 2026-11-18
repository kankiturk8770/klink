package com.gozar.app

import com.google.gson.annotations.SerializedName

/** One imported server profile. The raw link is kept verbatim so the Go engine
 *  re-parses it (single source of truth) when the tunnel starts. */
data class Profile(
    val id: String,
    val remark: String,
    val link: String,
    val protocol: String = "",
    val host: String = "",
    val port: Int = 0,
    val security: String = "",
)

enum class SpoofMode(val wire: String, val labelRes: Int) {
    NON_ROOT("non-root", R.string.mode_non_root),
    ROOT_ACTIVE("root-active", R.string.mode_root_active),
    ROOT_PASSIVE("root-passive", R.string.mode_root_passive),
    ROOT_RAW("root-raw", R.string.mode_root_raw);

    val isRoot: Boolean get() = this != NON_ROOT

    companion object {
        fun fromWire(w: String) = entries.firstOrNull { it.wire == w } ?: NON_ROOT
    }
}

/** User-facing advanced settings. Mirrors engine.SpoofSettings / engine.Settings. */
data class Settings(
    val activeProfileId: String? = null,
    val spoofEnabled: Boolean = true,
    val mode: SpoofMode = SpoofMode.NON_ROOT,
    val fakeSni: String = "",
    val utls: String = "chrome",

    val fakeRepeat: Int = 1,
    val fakeDelayMs: Int = 2,
    val ackTimeoutMs: Int = 2000,
    val enableFragment: Boolean = true,
    val fragmentDelayMs: Int = 2,
    val sniChunk: Int = 3,

    // non-root
    val fakeTtl: Int = 4,
    val fakeHoldMs: Int = 5,
    val tlsRecordSplit: Boolean = true,
    val disorder: Boolean = false,
    val disorderTtl: Int = 4,
    val oob: Boolean = false,

    val connectTimeoutMs: Int = 10000,

    val dns: String = "1.1.1.1",
    val logLevel: String = "warning",
    val sniffing: Boolean = true,
    val perAppEnabled: Boolean = false,
    val perAppAllow: Set<String> = emptySet(),
    val bypassLan: Boolean = true,
    val autoConnectOnBoot: Boolean = false,
)

/** JSON shape the Go engine expects (engine.Settings). Built by SettingsMapper. */
data class EngineSpoof(
    @SerializedName("Enabled") val enabled: Boolean,
    @SerializedName("FakeSNI") val fakeSni: String,
    @SerializedName("UTLS") val utls: String,
    @SerializedName("Mode") val mode: String,
    @SerializedName("FakeRepeat") val fakeRepeat: Int,
    @SerializedName("FakeDelayMS") val fakeDelayMs: Int,
    @SerializedName("AckTimeoutMS") val ackTimeoutMs: Int,
    @SerializedName("EnableFragment") val enableFragment: Boolean,
    @SerializedName("FragmentDelayMS") val fragmentDelayMs: Int,
    @SerializedName("SNIChunk") val sniChunk: Int,
    @SerializedName("FakeTTL") val fakeTtl: Int,
    @SerializedName("FakeHoldMS") val fakeHoldMs: Int,
    @SerializedName("TLSRecordSplit") val tlsRecordSplit: Boolean,
    @SerializedName("Disorder") val disorder: Boolean,
    @SerializedName("DisorderTTL") val disorderTtl: Int,
    @SerializedName("OOB") val oob: Boolean,
    @SerializedName("ConnectTimeoutMS") val connectTimeoutMs: Int,
)

data class EngineSettings(
    @SerializedName("Links") val links: List<String>,
    @SerializedName("Spoof") val spoof: EngineSpoof,
    @SerializedName("SocksPort") val socksPort: Int,
    @SerializedName("DNS") val dns: String,
    @SerializedName("LogLevel") val logLevel: String,
    @SerializedName("EnableSniffing") val enableSniffing: Boolean,
    @SerializedName("DialOverrideHost") val dialOverrideHost: String = "",
    @SerializedName("DialOverridePort") val dialOverridePort: Int = 0,
    /** Server IPv4 resolved by the app through the phone's real network. */
    @SerializedName("ServerIP") val serverIp: String = "",
)

/** Parsed link info — no network access involved. */
data class ProfileInfo(
    val remark: String = "",
    val protocol: String = "",
    val host: String = "",
    val port: Int = 0,
    val sni: String = "",
    val network: String = "",
    val security: String = "",
)

/** Server endpoint info resolved by the Go core (for the root-helper flow). */
data class ServerInfo(
    val host: String = "",
    val ip: String = "",
    val port: Int = 0,
    val sni: String = "",
    val protocol: String = "",
    val fakeSNI: String = "",
)

data class Stats(
    val active: Long = 0,
    val total: Long = 0,
    val failed: Long = 0,
    val bytesUp: Long = 0,
    val bytesDn: Long = 0,
    val fakeSent: Long = 0,
    val lastErr: String = "",
)

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED, ERROR }
