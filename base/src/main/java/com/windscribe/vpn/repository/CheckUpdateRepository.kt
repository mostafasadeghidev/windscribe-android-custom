/*
 * Copyright (c) 2021 Windscribe Limited.
 */
package com.windscribe.vpn.repository

import com.windscribe.vpn.api.response.CheckUpdateResponse
import com.windscribe.vpn.apppreference.PreferencesHelper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.slf4j.LoggerFactory
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CheckUpdateRepository
    @Inject
    constructor(
        private val preferencesHelper: PreferencesHelper,
    ) {
        private val logger = LoggerFactory.getLogger("update_check")

        private val _updateAvailable = MutableStateFlow<CheckUpdateResponse?>(null)
        val updateAvailable: StateFlow<CheckUpdateResponse?> = _updateAvailable

        private companion object {
            const val PROMPT_INTERVAL_MS = 72 * 60 * 60 * 1000L // 72 hours
        }

        fun checkForUpdate() {
            // This private build must never accept an update decision or installer URL from
            // Windscribe's production update service. Test APKs are obtained from this private
            // repository's GitHub Actions artifacts and installed by the owner.
            logger.info("Skipping Windscribe update service for the private GitHub build.")
            _updateAvailable.value = null
        }

        fun shouldShowPrompt(): Boolean {
            val lastPrompt = preferencesHelper.lastUpdatePromptTimestamp
            if (lastPrompt == 0L) return true
            return System.currentTimeMillis() - lastPrompt >= PROMPT_INTERVAL_MS
        }

        fun recordPromptShown() {
            preferencesHelper.lastUpdatePromptTimestamp = System.currentTimeMillis()
        }
    }
