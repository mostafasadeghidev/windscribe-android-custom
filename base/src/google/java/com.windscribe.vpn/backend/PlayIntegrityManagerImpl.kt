package com.windscribe.vpn.backend

import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.windscribe.vpn.BuildConfig
import com.windscribe.vpn.Windscribe.Companion.appContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Google Play flavor implementation of PlayIntegrityManager.
 * Uses Standard Play Integrity API to generate attestation tokens.
 */
@Singleton
class PlayIntegrityManagerImpl
    @Inject
    constructor() : PlayIntegrityManager {
        private val logger = LoggerFactory.getLogger("play-integrity")
        private val standardIntegrityManager = IntegrityManagerFactory.createStandard(appContext)
        private val cloudProjectNumber = BuildConfig.CLOUD_PROJECT_NUMBER.takeIf { it.isNotBlank() }?.toLongOrNull()

        private var tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

        /**
         * Synchronizes the initialization and retrieval of the [tokenProvider].
         * Ensures that if [warmUp] is currently executing, any concurrent calls
         * to [requestIntegrityToken] will suspend and wait for the warmup to
         * complete before proceeding.
         */
        private val mutex = Mutex()

        /**
         * Warms up the integrity token provider by preparing it with the cloud project number.
         * This should be called before requesting tokens to ensure the provider is ready.
         */
        private suspend fun warmUp(): Result<Unit> =
            mutex.withLock {
                if (tokenProvider != null) {
                    return Result.success(Unit)
                }

                if (cloudProjectNumber == null) {
                    logger.warn("Cloud project number not configured, cannot initialize integrity token provider")
                    return Result.failure(IllegalStateException("Cloud project number not configured"))
                }

                return runCatching {
                    logger.debug("Initializing Play Integrity token provider...")
                    val request =
                        StandardIntegrityManager.PrepareIntegrityTokenRequest
                            .builder()
                            .setCloudProjectNumber(cloudProjectNumber!!)
                            .build()
                    tokenProvider = standardIntegrityManager.prepareIntegrityToken(request).await()
                    logger.debug("Successfully initialized Play Integrity token provider")
                }.onFailure { error ->
                    logger.error("Failed to initialize integrity token provider: ${error.message}", error)
                }
            }

        override suspend fun requestIntegrityToken(): String? {
            if (cloudProjectNumber == null) {
                logger.warn("Cloud project number not configured, skipping integrity token request")
                return null
            }

            return try {
                // Generate a unique request hash for this token request
                val requestHash = generateSha256Hash(UUID.randomUUID().toString())

                // Ensure token provider is initialized
                var provider = mutex.withLock { tokenProvider }
                if (provider == null) {
                    warmUp().onFailure {
                        logger.error("Failed to warm up token provider")
                        return null
                    }
                    provider = mutex.withLock { tokenProvider }
                    if (provider == null) {
                        logger.error("Failed to initialize token provider after warmup")
                        return null
                    }
                }

                logger.debug("Requesting Play Integrity token with hash: $requestHash")

                val request =
                    StandardIntegrityManager.StandardIntegrityTokenRequest
                        .builder()
                        .setRequestHash(requestHash)
                        .build()

                val tokenResult = provider.request(request).await()
                val token = tokenResult.token()

                logger.debug("Successfully obtained Play Integrity token")
                token
            } catch (e: StandardIntegrityException) {
                logger.error("Play Integrity API error: ${e.errorCode} - ${e.message}", e)
                null
            } catch (e: Exception) {
                logger.error("Failed to request integrity token: ${e.message}", e)
                null
            }
        }

        override fun isAvailable(): Boolean = cloudProjectNumber != null

        /**
         * Computes an SHA-256 hash of the input string and encodes it as a
         * Base64 URL-safe, unpadded string.
         */
        private fun generateSha256Hash(input: String): String {
            val bytes = input.toByteArray(Charsets.UTF_8)
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(bytes)

            return Base64.encodeToString(
                digest,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            )
        }
    }
