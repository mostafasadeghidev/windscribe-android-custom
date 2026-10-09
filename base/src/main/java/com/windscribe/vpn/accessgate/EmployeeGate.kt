package com.windscribe.vpn.accessgate

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.windscribe.vpn.wsnet.WSNetWrapper
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import com.wsnet.lib.WSNetHttpNetworkManager
import java.security.SecureRandom
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** No Windscribe passwords are persisted. This store is separate from stock preferences. */
@Singleton
class EmployeeGate @Inject constructor(
    @ApplicationContext private val context: Context,
    private val wsnet: WSNetWrapper,
) {
    private val gson = Gson()
    private val mutex = Mutex()
    private val stateLock = Any()
    private val publicKey = Base64.decode("gXvJ2s3svrexi3YOwl0hNIT+7kJJQz2x0qFIYjPdbFs=", Base64.DEFAULT)
    private var httpManager: WSNetHttpNetworkManager? = null
    private val prefs by lazy {
        val master = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        EncryptedSharedPreferences.create(context, "employee_gate", master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }
    @Volatile private var state: GateState = runCatching {
        gson.fromJson(prefs.getString("state", null), GateState::class.java) ?: GateState()
    }.getOrDefault(GateState())
    @Volatile private var pending: GateState? = null
    /** True while the latest check could not reach or verify the access server. */
    @Volatile private var unreachable = state.token.isNotEmpty() && state.unreachableMs > 0
    @Volatile private var generation = 0L
    private var monitor: Job? = null
    private var scope: CoroutineScope? = null
    private var onRevoke: (() -> Unit)? = null
    private var nextCheck = 0L
    private var retry = 0
    private var checking: Job? = null

    /** A stored session never expires with time; only an explicit signed revocation clears it. */
    fun isAllowed(): Boolean = GatePolicy.hasSession(state)
    fun hasPending(): Boolean = pending != null
    fun username(): String = state.username
    private fun deviceId(): String {
        val existing = prefs.getString("device_id", null)
        if (existing != null) return existing
        val id = UUID.randomUUID().toString()
        check(prefs.edit().putString("device_id", id).commit()) { "Secure storage unavailable" }
        return id
    }

    fun start(scope: CoroutineScope, onRevoke: () -> Unit) {
        if (monitor != null) return
        this.scope = scope
        this.onRevoke = onRevoke
        monitor = scope.launch {
            // uptimeMillis is monotonic and stops in deep sleep, so neither clock changes nor sleep add time.
            var lastTick = SystemClock.uptimeMillis()
            var ticks = 0
            while (true) {
                val now = SystemClock.uptimeMillis()
                val step = now - lastTick
                lastTick = now
                synchronized(stateLock) {
                    if (unreachable && GatePolicy.hasSession(state)) {
                        state = GatePolicy.addUnreachable(state, step)
                        if (++ticks % GatePolicy.UNREACHABLE_SAVE_EVERY_TICKS == 0) persist(state)
                    }
                }
                if (isAllowed() && System.currentTimeMillis() >= nextCheck) checkSoon()
                delay(GatePolicy.UNREACHABLE_TICK_MS)
            }
        }
    }

    suspend fun login(username: String, password: String): Pair<String, String> = mutex.withLock {
        clear()
        val requestGeneration = generation
        val id = deviceId()
        val nonce = nonce()
        val body = JsonObject().apply {
            addProperty("username", username); addProperty("password", password)
            addProperty("device_id", id); addProperty("device_name", Build.MODEL)
            addProperty("platform", "android"); addProperty("app_version", "4.3-employee-test")
            addProperty("nonce", nonce)
        }
        val reply = post("login", body)
        val verified = verify(reply, username, id, nonce)
        require(verified["status"].asString == "active") { "Employee access disabled" }
        synchronized(stateLock) {
            check(generation == requestGeneration) { "Login was cancelled" }
            pending = makeState(verified, username, id, reply["token"].asString)
        }
        val credentials = reply["windscribe"].asJsonObject
        credentials["username"].asString to credentials["password"].asString
    }

    fun completeLogin(): Boolean = synchronized(stateLock) {
        val candidate = pending ?: return false
        return runCatching {
            check(prefs.edit().putString("state", gson.toJson(candidate)).commit())
            state = candidate; pending = null; nextCheck = 0; retry = 0; unreachable = false
            true
        }.getOrDefault(false)
    }

    fun clear() = synchronized(stateLock) {
        generation++
        pending = null
        state = state.copy(token = "", lastOkLocal = 0, lastOkServer = 0, unreachableMs = 0)
        unreachable = false
        persist(state)
        nextCheck = 0; retry = 0
    }

    private fun persist(value: GateState): Boolean =
        runCatching { prefs.edit().putString("state", gson.toJson(value)).commit() }.getOrDefault(false)

    private fun revoke() { clear(); onRevoke?.invoke() }

    /**
     * Check again now, cancelling a check still in flight. Called once the tunnel is up so a check that
     * could not reach the server on the open network is repeated through the tunnel.
     */
    fun recheckNow() {
        checking?.cancel()
        checking = null
        checkSoon()
    }

    fun checkSoon() {
        if (!isAllowed() || checking?.isActive == true) return
        checking = scope?.launch {
            val current = state
            val requestGeneration = generation
            try {
                val nonce = nonce()
                val reply = post("check", JsonObject().apply {
                    addProperty("username", current.username); addProperty("device_id", current.deviceId)
                    addProperty("token", current.token); addProperty("nonce", nonce)
                    addProperty("app_version", "4.3-employee-test")
                })
                val verified = verify(reply, current.username, current.deviceId, nonce)
                val revoked = synchronized(stateLock) {
                    if (generation != requestGeneration) return@launch
                    if (verified["status"].asString != "active") return@synchronized true
                    // A valid answer resets the unreachable streak (makeState starts it at zero).
                    val updated = makeState(verified, current.username, current.deviceId, current.token)
                    if (!persist(updated)) return@synchronized true
                    state = updated; retry = 0; unreachable = false
                    nextCheck = System.currentTimeMillis() + state.intervalSec * 1000
                    false
                }
                if (revoked) revoke()
            } catch (_: TimeoutCancellationException) {
                onUnreachable(current, requestGeneration)
            } catch (cancel: CancellationException) { throw cancel
            } catch (_: Exception) {
                onUnreachable(current, requestGeneration)
            }
        }
    }

    /** Not reaching the server never signs the user out by itself; only a long unreachable streak does. */
    private fun onUnreachable(current: GateState, requestGeneration: Long) {
        val tooLong = synchronized(stateLock) {
            if (generation != requestGeneration) return
            unreachable = true
            if (GatePolicy.unreachableTooLong(state)) return@synchronized true
            persist(state)
            val wait = longArrayOf(60, 300, 900).getOrElse(retry++) { current.intervalSec }
            nextCheck = System.currentTimeMillis() + wait * 1000
            false
        }
        if (tooLong) revoke()
    }

    private fun nonce(): String = Base64.encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) }, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun verify(reply: JsonObject, user: String, id: String, nonce: String): JsonObject {
        val envelope = reply["status"].asJsonObject
        return GatePolicy.verify(envelope["payload"].asString, envelope["sig"].asString, publicKey, user, id, nonce)
    }
    private fun makeState(status: JsonObject, user: String, id: String, token: String) = GateState(
        user, id, token, System.currentTimeMillis(), status["server_time"].asLong,
        status["offline_grace_sec"].asLong, status["check_interval_sec"].asLong)

    private suspend fun post(path: String, body: JsonObject): JsonObject = withTimeout(21000) {
        wsnet.awaitServerAPI()
        val manager = httpManager ?: checkNotNull(wsnet.getInstance()).httpNetworkManager().also { httpManager = it }
        val request = manager.createPostRequest("https://wind-gate.throbbing-boat-c9fc.workers.dev/api/v1/$path", 20000, body.toString(), false)
        request.addHttpHeader("Content-Type: application/json")
        suspendCancellableCoroutine { continuation ->
            val callback = manager.executeRequest(request, 0) { _, _, error, data ->
                if (continuation.isActive) {
                    try {
                        check(error.isSuccess && error.httpResponseCode() == 200) { "Employee request failed (${error.httpResponseCode()})" }
                        require(data.toByteArray().size <= 65536)
                        continuation.resume(com.google.gson.JsonParser.parseString(data).asJsonObject)
                    } catch (e: Exception) { continuation.resumeWithException(e) }
                }
            }
            continuation.invokeOnCancellation { callback.cancel() }
        }
    }
}
