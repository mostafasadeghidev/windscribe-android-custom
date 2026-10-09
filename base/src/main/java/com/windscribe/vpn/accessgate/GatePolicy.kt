package com.windscribe.vpn.accessgate

import com.google.gson.JsonParser
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.MessageDigest
import java.util.Base64

data class GateState(
    val username: String = "",
    val deviceId: String = "",
    val token: String = "",
    val lastOkLocal: Long = 0,
    val lastOkServer: Long = 0,
    val graceSec: Long = 0,
    val intervalSec: Long = 3600,
    /** App running time since the last valid answer, counted only while checks are failing. */
    val unreachableMs: Long = 0,
)

/**
 * A session never expires with wall-clock time; only an explicit signed revocation ends it. As a guard
 * against blocking the access server on purpose, the device is locked after [MAX_UNREACHABLE_MS] of app
 * running time without a single valid answer. Time while the app is not running or the device sleeps
 * is not counted.
 */
object GatePolicy {
    const val MAX_UNREACHABLE_MS = 7L * 24 * 60 * 60 * 1000
    /** Largest step one monitor tick may add; larger gaps are sleep or a stalled process. */
    const val MAX_UNREACHABLE_STEP_MS = 30_000L
    const val UNREACHABLE_TICK_MS = 10_000L
    const val UNREACHABLE_SAVE_EVERY_TICKS = 6

    fun hasSession(state: GateState): Boolean = state.token.isNotEmpty()

    fun addUnreachable(state: GateState, elapsedMs: Long): GateState =
        state.copy(unreachableMs = state.unreachableMs + elapsedMs.coerceIn(0, MAX_UNREACHABLE_STEP_MS))

    fun unreachableTooLong(state: GateState): Boolean = state.unreachableMs >= MAX_UNREACHABLE_MS

    fun verify(
        payload: String,
        signature: String,
        key: ByteArray,
        username: String,
        deviceId: String,
        nonce: String,
    ): com.google.gson.JsonObject {
        require(payload.length <= 65536)
        val curve = EdDSANamedCurveTable.getByName("Ed25519")
        val verifier = EdDSAEngine(MessageDigest.getInstance("SHA-512"))
        verifier.initVerify(EdDSAPublicKey(EdDSAPublicKeySpec(key, curve)))
        verifier.update(payload.toByteArray(Charsets.UTF_8))
        require(verifier.verify(Base64.getUrlDecoder().decode(signature))) { "Invalid access signature" }
        val status = JsonParser.parseString(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)).asJsonObject
        require(status["v"].asInt == 1 && status["type"].asString == "status")
        require(status["username"].asString == username && status["device_id"].asString == deviceId && status["nonce"].asString == nonce)
        require(status["server_time"].asLong > 0)
        require(status["offline_grace_sec"].asLong in 1..172800 && status["check_interval_sec"].asLong in 1..86400)
        return status
    }
}
