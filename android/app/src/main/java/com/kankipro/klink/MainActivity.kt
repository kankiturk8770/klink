package com.kankipro.klink

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import mobile.Mobile
import java.util.concurrent.Executors
import kotlin.math.ln
import kotlin.math.pow

class MainActivity : Activity() {
    private lateinit var store: ConfigStore
    private lateinit var connectButton: Button
    private lateinit var statusText: TextView
    private lateinit var statusDetail: TextView
    private lateinit var profileName: TextView
    private lateinit var networkText: TextView
    private lateinit var speedText: TextView
    private lateinit var errorText: TextView
    private lateinit var progress: ProgressBar
    private val handler = Handler(Looper.getMainLooper())
    private val io = Executors.newSingleThreadExecutor()

    private val poller = object : Runnable {
        override fun run() {
            renderState()
            handler.postDelayed(this, 700)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        store = ConfigStore(this)
        connectButton = findViewById(R.id.connectButton)
        statusText = findViewById(R.id.statusText)
        statusDetail = findViewById(R.id.statusDetail)
        profileName = findViewById(R.id.profileName)
        networkText = findViewById(R.id.networkText)
        speedText = findViewById(R.id.speedText)
        errorText = findViewById(R.id.errorText)
        progress = findViewById(R.id.progress)
        profileName.text = store.profileName()

        findViewById<ImageButton>(R.id.addButton).setOnClickListener {
            if (Mobile.state() != Mobile.StateDisconnected) {
                Toast.makeText(this, "برای تعویض اشتراک ابتدا اتصال را قطع کنید", Toast.LENGTH_SHORT).show()
            } else {
                showSubscriptionDialog()
            }
        }
        connectButton.setOnClickListener {
            if (Mobile.state() == Mobile.StateDisconnected) requestConnection() else stopConnection()
        }
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 42)
        }
        renderState()
    }

    private fun requestConnection() {
        if (store.load() == null) {
            showSubscriptionDialog()
            return
        }
        errorText.visibility = View.GONE
        val permission = VpnService.prepare(this)
        if (permission != null) {
            @Suppress("DEPRECATION") startActivityForResult(permission, VPN_REQUEST)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, KlinkVpnService::class.java).setAction(KlinkVpnService.ACTION_CONNECT)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        statusText.text = "در حال اتصال"
        statusDetail.text = "در حال ساخت مسیر امن…"
        connectButton.text = "لغو"
    }

    private fun stopConnection() {
        connectButton.isEnabled = false
        statusDetail.text = "در حال قطع اتصال…"
        startService(Intent(this, KlinkVpnService::class.java).setAction(KlinkVpnService.ACTION_STOP))
        // If the service died before completing its startup, the explicit core
        // stop still cancels a pending handshake.
        io.execute { if (Mobile.state() != Mobile.StateDisconnected) Mobile.stop() }
    }

    @Deprecated("Deprecated Android activity result API; kept dependency-free")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) startVpnService()
            else Toast.makeText(this, "اجازه‌ی VPN داده نشد", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showSubscriptionDialog() {
        val input = EditText(this).apply {
            hint = "https://panel.example.com/sub/…"
            textDirection = View.TEXT_DIRECTION_LTR
            layoutDirection = View.LAYOUT_DIRECTION_LTR
            gravity = Gravity.TOP or Gravity.START
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 3
            maxLines = 5
            setSingleLine(false)
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            textSize = 13f
        }
        val container = FrameLayout(this)
        val margin = dp(20)
        container.setPadding(margin, dp(8), margin, 0)
        container.addView(input, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))
        val dialog = AlertDialog.Builder(this)
            .setTitle("افزودن لینک اشتراک")
            .setMessage("لینک را بچسبانید؛ کلیدها فقط رمزشده روی دستگاه نگه داشته می‌شوند.")
            .setView(container)
            .setNegativeButton("انصراف", null)
            .setPositiveButton("دریافت و ذخیره", null)
            .create()
        dialog.setOnShowListener {
            val save = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            save.setOnClickListener {
                val value = input.text.toString().trim()
                if (value.isEmpty()) {
                    input.error = "لینک را وارد کنید"
                    return@setOnClickListener
                }
                save.isEnabled = false
                input.isEnabled = false
                io.execute {
                    try {
                        val config = Mobile.fetchSubscription(value)
                        runOnUiThread {
                            if (isDestroyed) return@runOnUiThread
                            store.save(config)
                            profileName.text = store.profileName()
                            errorText.visibility = View.GONE
                            dialog.dismiss()
                            Toast.makeText(this, if (value.startsWith("http://"))
                                "ذخیره شد؛ برای امنیت بیشتر از HTTPS استفاده کنید" else "اشتراک با موفقیت اضافه شد", Toast.LENGTH_LONG).show()
                            renderState()
                        }
                    } catch (error: Exception) {
                        runOnUiThread {
                            if (isDestroyed) return@runOnUiThread
                            save.isEnabled = true
                            input.isEnabled = true
                            input.error = error.message ?: "دریافت اشتراک ناموفق بود"
                            Toast.makeText(this, error.message ?: "خطا در اشتراک", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
        }
        dialog.show()
        // setOnShowListener is installed before showing below when needed.
        if (!dialog.isShowing) dialog.show()
    }

    private fun renderState() {
        if (::connectButton.isInitialized.not()) return
        val state = Mobile.state()
        connectButton.isEnabled = true
        progress.visibility = if (state == Mobile.StateConnecting || state == Mobile.StateReconnecting) View.VISIBLE else View.GONE
        when (state) {
            Mobile.StateConnected -> {
                statusText.text = "متصل"
                statusText.setTextColor(getColor(R.color.connected))
                statusDetail.text = "اتصال رمزنگاری‌شده برقرار است"
                connectButton.text = "قطع اتصال"
            }
            Mobile.StateConnecting -> {
                statusText.text = "در حال اتصال"
                statusText.setTextColor(getColor(R.color.accent))
                statusDetail.text = "handshake و بررسی مسیر سرور…"
                connectButton.text = "لغو"
            }
            Mobile.StateReconnecting -> {
                statusText.text = "در حال بازیابی"
                statusText.setTextColor(getColor(R.color.warning))
                statusDetail.text = "تعویض شبکه یا مسیر UDP/TCP…"
                connectButton.text = "قطع اتصال"
            }
            else -> {
                statusText.text = "قطع"
                statusText.setTextColor(getColor(R.color.text))
                statusDetail.text = if (store.hasConfig()) "آماده‌ی اتصال" else "با دکمه‌ی + یک اشتراک اضافه کنید"
                connectButton.text = "اتصال"
                speedText.text = "↑ 0 B/s   ↓ 0 B/s"
            }
        }
        val liveNetwork = Mobile.network()
        networkText.text = if (liveNetwork.isBlank()) "UDP / TCP" else "مسیر ${liveNetwork.uppercase()}"
        if (state != Mobile.StateDisconnected) {
            speedText.text = "↑ ${formatRate(Mobile.uploadSpeed())}   ↓ ${formatRate(Mobile.downloadSpeed())}"
        }
        val error = Mobile.lastError().ifBlank { KlinkVpnService.serviceError.orEmpty() }
        errorText.text = error
        errorText.visibility = if (error.isBlank() || state == Mobile.StateConnected) View.GONE else View.VISIBLE
    }

    private fun formatRate(bytesPerSecond: Long): String {
        if (bytesPerSecond <= 0) return "0 B/s"
        val units = arrayOf("B/s", "KB/s", "MB/s", "GB/s")
        val index = ((ln(bytesPerSecond.toDouble()) / ln(1024.0)).toInt()).coerceIn(0, units.lastIndex)
        val value = bytesPerSecond / 1024.0.pow(index)
        return String.format("%.1f %s", value, units[index])
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    override fun onResume() { super.onResume(); handler.post(poller) }
    override fun onPause() { handler.removeCallbacks(poller); super.onPause() }
    override fun onDestroy() { handler.removeCallbacks(poller); io.shutdownNow(); super.onDestroy() }

    companion object { private const val VPN_REQUEST = 4101 }
}
