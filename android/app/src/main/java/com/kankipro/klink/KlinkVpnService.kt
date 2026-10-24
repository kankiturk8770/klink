package com.kankipro.klink

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import mobile.Mobile
import java.util.concurrent.Executors

class KlinkVpnService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var running = false
    @Volatile private var stopping = false
    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> shutdown()
            ACTION_CONNECT -> if (!running) connect()
        }
        return START_NOT_STICKY
    }

    private fun connect() {
        running = true
        stopping = false
        serviceError = null
        startVpnForeground()
        val config = ConfigStore(this).load()
        if (config == null) {
            serviceError = "ابتدا با دکمه‌ی + یک اشتراک اضافه کنید"
            running = false
            stopSelf()
            return
        }
        worker.execute {
            try {
                val builder = Builder()
                    .setSession("KLINK/1")
                    .setMtu(1500)
                    .setBlocking(true)
                    .addAddress("10.231.0.2", 32)
                    .addAddress("fd00:1:1:1::2", 128)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("2606:4700:4700::1111")
                // KLINK's own encrypted sockets must bypass its TUN; otherwise
                // every packet recursively enters the VPN and connection fails.
                builder.addDisallowedApplication(packageName)
                val descriptor = builder.establish() ?: throw IllegalStateException("سیستم اجازه‌ی ساخت TUN نداد")
                tun = descriptor
                val fd = descriptor.detachFd()
                tun = null // Go owns fd from this point onward, including errors.
                Mobile.start(fd.toLong(), config)
                if (Mobile.state() != Mobile.StateConnected) {
                    throw IllegalStateException(Mobile.lastError().ifBlank { "اتصال برقرار نشد" })
                }
            } catch (error: Throwable) {
                serviceError = error.message ?: Mobile.lastError().ifBlank { "اتصال VPN ناموفق بود" }
                Mobile.stop()
                stopSelf()
            } finally {
                running = false
            }
        }
    }

    private fun shutdown() {
        if (stopping) return
        stopping = true
        Thread {
            Mobile.stop()
            tun?.close()
            tun = null
            running = false
            stopSelf()
        }.start()
    }

    private fun startVpnForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID,
                getString(R.string.vpn_channel), NotificationManager.IMPORTANCE_LOW))
        }
        val openIntent = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stopIntent = PendingIntent.getService(this, 1,
            Intent(this, KlinkVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notificationBuilder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        val notification = notificationBuilder
            .setSmallIcon(R.drawable.ic_logo)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(openIntent)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.notification_stop), stopIntent).build())
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onRevoke() {
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (!stopping) Mobile.stop()
        tun?.close()
        tun = null
        worker.shutdownNow()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    companion object {
        @Volatile var serviceError: String? = null
            private set
        const val ACTION_CONNECT = "com.kankipro.klink.CONNECT"
        const val ACTION_STOP = "com.kankipro.klink.STOP"
        private const val CHANNEL_ID = "klink.vpn"
        private const val NOTIFICATION_ID = 41
    }
}
