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
)

object GatePolicy {
    fun withinGrace(state: GateState, now: Long): Boolean =
        state.token.isNotEmpty() && state.lastOkLocal > 0 && state.graceSec in 1..172800 &&
            now >= state.lastOkLocal - 300000 && now - state.lastOkLocal <= state.graceSec * 1000

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
