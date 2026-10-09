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

    @Test fun sessionNeverExpiresWithTime() {
        // A device left unused for a month keeps its session; only a revocation or sign-out clears the token.
        val month = GateState(token = "token", lastOkLocal = 1, graceSec = 172800)
        assertTrue(GatePolicy.hasSession(month))
        assertFalse(GatePolicy.unreachableTooLong(month))
        assertFalse(GatePolicy.hasSession(month.copy(token = "")))
    }

    @Test fun unreachableTimeIsCappedPerStepAndLocksAtLimit() {
        val state = GateState(token = "token")
        assertEquals(10_000L, GatePolicy.addUnreachable(state, 10_000).unreachableMs)
        // A sleep or stalled-process gap adds at most one step.
        assertEquals(GatePolicy.MAX_UNREACHABLE_STEP_MS, GatePolicy.addUnreachable(state, 7L * 86_400_000).unreachableMs)
        assertEquals(0L, GatePolicy.addUnreachable(state, -5_000).unreachableMs)
        assertFalse(GatePolicy.unreachableTooLong(state.copy(unreachableMs = GatePolicy.MAX_UNREACHABLE_MS - 1)))
        assertTrue(GatePolicy.unreachableTooLong(state.copy(unreachableMs = GatePolicy.MAX_UNREACHABLE_MS)))
    }

    @Test fun storedStateFromEarlierBuildsLoadsWithZeroUnreachableTime() {
        val old = """{"username":"employee","deviceId":"device","token":"token","lastOkLocal":1,"lastOkServer":1,"graceSec":172800,"intervalSec":3600}"""
        val state = com.google.gson.Gson().fromJson(old, GateState::class.java)
        assertTrue(GatePolicy.hasSession(state))
        assertEquals(0L, state.unreachableMs)
    }
}
