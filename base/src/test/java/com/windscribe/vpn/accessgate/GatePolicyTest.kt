package com.windscribe.vpn.accessgate

import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class GatePolicyTest {
    private val key = EdDSAPrivateKeySpec(ByteArray(32) { it.toByte() }, EdDSANamedCurveTable.getByName("Ed25519"))
    private fun signed(status: String = "active", grace: Long = 172800): Pair<String, String> {
        val json = """{"v":1,"type":"status","username":"employee","device_id":"device","nonce":"fresh","status":"$status","server_time":1000,"offline_grace_sec":$grace,"check_interval_sec":3600}"""
        val payload = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        val signer = EdDSAEngine(MessageDigest.getInstance("SHA-512"))
        signer.initSign(EdDSAPrivateKey(key))
        signer.update(payload.toByteArray())
        return payload to Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign())
    }

    @Test fun signedActiveAndRevokedStatusesVerify() {
        for (status in listOf("active", "disabled", "device_revoked", "unknown_user")) {
            val (payload, signature) = signed(status)
            assertEquals(status, GatePolicy.verify(payload, signature, key.a.toByteArray(), "employee", "device", "fresh")["status"].asString)
        }
    }

    @Test fun tamperingAndBindingChangesAreRejected() {
        val (payload, signature) = signed()
        assertThrows(IllegalArgumentException::class.java) { GatePolicy.verify(payload.dropLast(1) + "A", signature, key.a.toByteArray(), "employee", "device", "fresh") }
        for ((user, device, nonce) in listOf(Triple("other", "device", "fresh"), Triple("employee", "other", "fresh"), Triple("employee", "device", "replay"))) {
            assertThrows(IllegalArgumentException::class.java) { GatePolicy.verify(payload, signature, key.a.toByteArray(), user, device, nonce) }
        }
        val (tooLong, sig) = signed(grace = 172801)
        assertThrows(IllegalArgumentException::class.java) { GatePolicy.verify(tooLong, sig, key.a.toByteArray(), "employee", "device", "fresh") }
    }

    @Test fun graceExpiresAndClockRollbackFailsClosed() {
        val state = GateState(token = "token", lastOkLocal = 1_000_000, graceSec = 172800)
        assertTrue(GatePolicy.withinGrace(state, 1_000_000 + 172800_000))
        assertFalse(GatePolicy.withinGrace(state, 1_000_000 + 172800_001))
        assertFalse(GatePolicy.withinGrace(state, 699999))
        assertFalse(GatePolicy.withinGrace(state.copy(token = ""), 1_000_000))
    }
}
