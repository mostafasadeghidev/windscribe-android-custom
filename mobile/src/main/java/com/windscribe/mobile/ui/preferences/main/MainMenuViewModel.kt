package com.windscribe.mobile.ui.preferences.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.windscribe.vpn.commonutils.HashUtils
import com.windscribe.vpn.repository.UserRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

abstract class MainMenuViewModel : ViewModel() {
    abstract val showReferData: Boolean

    abstract fun logout()

    abstract val showProgress: StateFlow<Boolean>
}

@HiltViewModel
class MainMenuViewModelImpl
    @Inject
    constructor(
        val userRepository: UserRepository,
    ) : MainMenuViewModel() {
        override val showReferData: Boolean
            get() {
                val user = userRepository.user.value ?: return false
                // The referral flow asks the user to share their username. For hashed accounts the
                // username is also the password, so sharing it hands over the account.
                return !user.isPro && !HashUtils.isAccountHash(user.userName)
            }

        private val _showProgress = MutableStateFlow(false)
        override val showProgress: StateFlow<Boolean> = _showProgress

        override fun logout() {
            viewModelScope.launch {
                _showProgress.value = true
                userRepository.logout()
                _showProgress.value = false
            }
        }
    }
