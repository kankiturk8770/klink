package com.gozar.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * The VpnService: builds the TUN, starts the Go engine (and, in root mode, the
 * external gozar-helper), feeds the TUN fd to the engine's tun2socks, and keeps
 * a foreground notification + live stats while connected.
 */
class GozarVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var rootHelper: RootHelper? = null
    private val scope = CoroutineScope(Dispatchers.IO)
    private var statsJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            VpnController.ACTION_STOP -> { stopTunnel(); return START_NOT_STICKY }
            else -> startForegroundServiceSafe()
        }
        scope.launch { startTunnel() }
        return START_STICKY
    }

    private suspend fun startTunnel() {
        VpnController.setState(VpnState.CONNECTING)
        val store = Store(applicationContext)
        val settings = store.settingsBlocking()
        val profiles = store.profilesBlocking()
        val active = profiles.firstOrNull { it.id == settings.activeProfileId }
            ?: profiles.firstOrNull()
        if (active == null) {
            GoBridge.log("ERROR: no profile selected")
            VpnController.setError("no active profile")
            stopSelf(); return
        }

        GoBridge.setLogCallback { /* kept in Go ring buffer; UI reads Logs() */ }
        GoBridge.setProtect { fd -> protect(fd) }

        try {
            var helperHost = ""
            var helperPort = 0

            GoBridge.log("connecting: ${active.remark} (mode ${settings.mode.wire})")
            val info = runCatching { GoBridge.profileInfo(active.link) }.getOrElse {
                throw IllegalStateException("invalid config: ${it.message}")
            }
            GoBridge.log("server ${info.host}:${info.port} ${info.protocol}/${info.network}/${info.security} sni=${info.sni}")

            // Resolve the server through the phone's real network BEFORE the VPN
            // exists (Android has no /etc/resolv.conf for Go's resolver).
            val serverIp = resolveServer(info.host)
            if (serverIp.isNotEmpty()) GoBridge.log("resolved ${info.host} -> $serverIp (system DNS)")
            else GoBridge.log("WARN: system DNS could not resolve ${info.host}; engine will try public DNS")

            if (settings.mode.isRoot) {
                val helper = RootHelper(applicationContext).also { rootHelper = it }
                if (!helper.hasRoot()) throw IllegalStateException("root not available (su denied or missing)")
                if (serverIp.isEmpty()) throw IllegalStateException("could not resolve ${info.host}")
                val ifaceName = activeInterfaceName()
                val req = RootHelper.Request(
                    connectIP = serverIp,
                    connectPort = info.port,
                    fakeSNI = settings.fakeSni.ifEmpty { "www.cloudflare.com" },
                    utls = settings.utls,
                    mode = settings.mode.wire.removePrefix("root-"),
                    interfaceName = ifaceName,
                    fakeRepeat = settings.fakeRepeat,
                    fakeDelayMS = settings.fakeDelayMs,
                    ackTimeoutMS = settings.ackTimeoutMs,
                    enableFragment = settings.enableFragment,
                    fragmentDelayMS = settings.fragmentDelayMs,
                    sniChunk = settings.sniChunk,
                )
                val addr = helper.start(req) { GoBridge.log(it) }
                val idx = addr.lastIndexOf(':')
                helperHost = addr.substring(0, idx).ifEmpty { "127.0.0.1" }
                helperPort = addr.substring(idx + 1).toInt()
            }

            val mtu = 1500
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(mtu)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(settings.dns.ifEmpty { "1.1.1.1" })
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

            // IPv6 opt-in route so v6-only apps don't bypass; harmless if unused.
            runCatching { builder.addAddress("fd00::2", 128).addRoute("::", 0) }

            if (settings.bypassLan) {
                // Exclude RFC1918 / link-local from the tunnel.
                for (r in lanBypassRoutes()) runCatching { builder.addRoute(r.first, r.second) }
            }

            // Per-app routing.
            if (settings.perAppEnabled && settings.perAppAllow.isNotEmpty()) {
                for (pkg in settings.perAppAllow) runCatching { builder.addAllowedApplication(pkg) }
            } else {
                // Never tunnel ourselves (avoids loops with the helper / xray).
                runCatching { builder.addDisallowedApplication(packageName) }
            }

            val pfd = builder.establish()
                ?: throw IllegalStateException("VPN permission revoked or another VPN is always-on")
            tun = pfd
            GoBridge.log("VPN interface up")

            val engineSettings = SettingsMapper.toEngine(settings, active.link, 0, helperHost, helperPort, serverIp)
            GoBridge.start(engineSettings, pfd.fd, mtu)

            GoBridge.log("connected")
            VpnController.setState(VpnState.CONNECTED)
            updateNotification(active.remark)
            startStatsLoop()
        } catch (t: Throwable) {
            val msg = t.message ?: t.toString()
            GoBridge.log("ERROR: $msg")
            VpnController.setError(msg)
            stopTunnel()
        }
    }

    /** Resolves host to IPv4 via the active (physical) network's system DNS. "" on failure. */
    private fun resolveServer(host: String): String {
        if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) return host
        val cm = getSystemService(ConnectivityManager::class.java)
        val attempts = listOf<() -> Array<java.net.InetAddress>?>(
            { cm.activeNetwork?.getAllByName(host) },
            { java.net.InetAddress.getAllByName(host) },
        )
        for (a in attempts) {
            val r = runCatching { a() }
            r.exceptionOrNull()?.let { GoBridge.log("system DNS: ${it.javaClass.simpleName}: ${it.message}") }
            r.getOrNull()?.firstOrNull { it is java.net.Inet4Address }?.hostAddress?.let { return it }
        }
        return ""
    }

    private fun startStatsLoop() {
        statsJob?.cancel()
        statsJob = scope.launch {
            while (isActive) {
                runCatching { VpnController.setStats(GoBridge.stats()) }
                delay(1000)
            }
        }
    }

    private fun stopTunnel() {
        statsJob?.cancel(); statsJob = null
        runCatching { GoBridge.stop() }
        runCatching { rootHelper?.stop() }
        rootHelper = null
        runCatching { tun?.close() }
        tun = null
        VpnController.setState(VpnState.DISCONNECTED)
        stopForegroundCompat()
        stopSelf()
    }

    override fun onRevoke() { stopTunnel() }
    override fun onDestroy() { statsJob?.cancel(); scope.coroutineContext[Job]?.cancel(); super.onDestroy() }

    private fun activeInterfaceName(): String {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.activeNetwork ?: return ""
        val lp = cm.getLinkProperties(net) ?: return ""
        return lp.interfaceName ?: ""
    }

    // Notification ------------------------------------------------------------
    private val channelId = "gozar_vpn"
    private val notifId = 1001

    private fun startForegroundServiceSafe() {
        ensureChannel()
        val n = buildNotification(getString(R.string.notif_connecting))
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(notifId, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(notifId, n)
        }
    }

    private fun updateNotification(remark: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(notifId, buildNotification(getString(R.string.notif_connected, remark)))
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(channelId, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, GozarVpnService::class.java).setAction(VpnController.ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, channelId) else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, getString(R.string.disconnect), stop).build())
            .build()
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        else @Suppress("DEPRECATION") stopForeground(true)
    }

    private fun lanBypassRoutes(): List<Pair<String, Int>> = listOf(
        "10.0.0.0" to 8, "172.16.0.0" to 12, "192.168.0.0" to 16,
        "169.254.0.0" to 16, "127.0.0.0" to 8,
    )

    companion object {
        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, GozarVpnService::class.java).setAction(VpnController.ACTION_START))
        }
        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, GozarVpnService::class.java).setAction(VpnController.ACTION_STOP))
        }
    }
}
