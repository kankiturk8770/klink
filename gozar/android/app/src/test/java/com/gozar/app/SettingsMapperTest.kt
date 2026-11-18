package com.gozar.app

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Verifies the UI Settings -> engine JSON contract that the Go core consumes. */
class SettingsMapperTest {
    private val gson = Gson()

    @Test fun nonRootKeepsSpoofEnabledAndNoOverride() {
        val s = Settings(mode = SpoofMode.NON_ROOT, spoofEnabled = true, fakeSni = "www.cloudflare.com", sniChunk = 2)
        val e = SettingsMapper.toEngine(s, "vless://x@1.2.3.4:443?security=tls&type=tcp#a", 1080)
        assertTrue(e.spoof.enabled)
        assertEquals("non-root", e.spoof.mode)
        assertEquals("www.cloudflare.com", e.spoof.fakeSni)
        assertEquals(2, e.spoof.sniChunk)
        assertEquals("", e.dialOverrideHost)
        assertEquals(0, e.dialOverridePort)
        // Round-trips to the field names Go expects (PascalCase via @SerializedName).
        val json = gson.toJson(e)
        assertTrue(json.contains("\"Spoof\""))
        assertTrue(json.contains("\"FakeSNI\""))
        assertTrue(json.contains("\"TLSRecordSplit\""))
    }

    @Test fun rootModeMovesSpoofToHelperViaOverride() {
        val s = Settings(mode = SpoofMode.ROOT_ACTIVE, spoofEnabled = true)
        val e = SettingsMapper.toEngine(s, "vless://x@1.2.3.4:443?security=tls&type=tcp#a", 1080, "127.0.0.1", 42000)
        // In root mode the in-engine spoof is disabled; Xray dials the helper.
        assertFalse(e.spoof.enabled)
        assertEquals("127.0.0.1", e.dialOverrideHost)
        assertEquals(42000, e.dialOverridePort)
    }

    @Test fun modeWireValues() {
        assertEquals("non-root", SpoofMode.NON_ROOT.wire)
        assertEquals("root-active", SpoofMode.ROOT_ACTIVE.wire)
        assertEquals("root-raw", SpoofMode.ROOT_RAW.wire)
        assertEquals(SpoofMode.ROOT_PASSIVE, SpoofMode.fromWire("root-passive"))
        assertTrue(SpoofMode.ROOT_ACTIVE.isRoot)
        assertFalse(SpoofMode.NON_ROOT.isRoot)
    }
}
