package com.gozar.app

import android.content.Context
import com.google.gson.Gson
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Drives the privileged packet-injection helper (gozar-helper) in a root
 * domain via `su`. The helper is shipped as a native library
 * (libgozarhelper.so) so Android extracts it into nativeLibraryDir with execute
 * permission (an app may not exec a binary from its writable data dir on modern
 * Android). We `su -c "<helper> -"` and write the JSON request to its stdin;
 * the helper runs the SNI-spoofing proxy as root and prints its listen address.
 *
 * Root mode is experimental: it requires a rooted device with a working `su`.
 */
class RootHelper(private val context: Context) {
    private val gson = Gson()
    @Volatile private var process: Process? = null

    data class Request(
        val connectIP: String,
        val connectPort: Int,
        val fakeSNI: String,
        val utls: String,
        val mode: String,
        val listenHost: String = "127.0.0.1",
        val listenPort: Int = 0,
        val interfaceName: String = "",
        val interfaceIP: String = "",
        val fwMark: Int = 0,
        val mtu: Int = 0,
        val fakeRepeat: Int = 1,
        val fakeDelayMS: Int = 2,
        val ackTimeoutMS: Int = 2000,
        val enableFragment: Boolean = false,
        val fragmentDelayMS: Int = 2,
        val sniChunk: Int = 3,
    )

    data class Response(val ok: Boolean = false, val listenAddr: String = "", val error: String = "")

    private fun helperPath(): String {
        val lib = File(context.applicationInfo.nativeLibraryDir, "libgozarhelper.so")
        return lib.absolutePath
    }

    /** @return true if `su` is present and grants root. */
    fun hasRoot(): Boolean = runCatching {
        val p = ProcessBuilder("su", "-c", "id -u").redirectErrorStream(true).start()
        val out = BufferedReader(InputStreamReader(p.inputStream)).readLine()?.trim()
        p.waitFor()
        out == "0"
    }.getOrDefault(false)

    /**
     * Starts the helper and returns the bound "host:port" it is listening on.
     * Throws on failure. The process keeps running until [stop].
     */
    fun start(req: Request, log: (String) -> Unit): String {
        val helper = helperPath()
        if (!File(helper).exists()) {
            throw IllegalStateException("gozar-helper native binary not found at $helper")
        }
        // chmod via su in case the extracted bit was stripped, then exec.
        val cmd = "chmod 700 '$helper' 2>/dev/null; exec '$helper' -"
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(false).start()
        process = p

        p.outputStream.write((gson.toJson(req) + "\n").toByteArray())
        p.outputStream.flush()
        // keep stdin open: the helper exits when it closes (parent-death link)

        // Drain stderr to the log.
        Thread {
            runCatching {
                BufferedReader(InputStreamReader(p.errorStream)).forEachLine { log("helper: $it") }
            }
        }.apply { isDaemon = true }.start()

        val reader = BufferedReader(InputStreamReader(p.inputStream))
        val line = reader.readLine() ?: throw IllegalStateException("helper produced no output (no root?)")
        val resp = runCatching { gson.fromJson(line, Response::class.java) }.getOrNull()
            ?: throw IllegalStateException("helper bad response: $line")
        if (!resp.ok || resp.listenAddr.isEmpty()) {
            stop()
            throw IllegalStateException("helper error: ${resp.error.ifEmpty { "unknown" }}")
        }
        // Keep reading remaining stdout into the log.
        Thread {
            runCatching { reader.forEachLine { log("helper: $it") } }
        }.apply { isDaemon = true }.start()
        return resp.listenAddr
    }

    fun stop() {
        val p = process ?: return
        process = null
        runCatching { p.outputStream.close() } // signals parent-death to the helper
        runCatching { p.destroy() }
    }
}
