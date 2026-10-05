package com.windscribe.mobile.ui.auth

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.windscribe.mobile.ui.helper.AccessibilityHelper
import com.windscribe.vpn.BuildConfig
import com.windscribe.vpn.api.IApiCallManager
import com.windscribe.vpn.api.response.AuthToken
import com.windscribe.vpn.api.response.UserLoginResponse
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.commonutils.Ext.result
import com.windscribe.vpn.commonutils.HashUtils
import com.windscribe.vpn.commonutils.WindUtilities
import com.windscribe.vpn.constants.NetworkErrorCodes
import com.windscribe.vpn.errormodel.SessionErrorHandler
import com.windscribe.vpn.exceptions.ApiFailure
import com.windscribe.vpn.repository.CallResult
import com.windscribe.vpn.repository.UserDataState
import com.windscribe.vpn.repository.UserRepository
import com.windscribe.vpn.repository.getNetworkError
import com.windscribe.vpn.services.FirebaseManager
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import javax.inject.Inject

sealed class LoginState {
    object Idle : LoginState()

    data class LoggingIn(
        val message: String,
    ) : LoginState()

    data class Captcha(
        val request: CaptchaRequest,
        val error: String? = null,
        val refreshing: Boolean = false,
    ) : LoginState()

    object Success : LoginState()

    data class Error(
        val errorType: AuthError,
    ) : LoginState()
}

@HiltViewModel
class LoginViewModel
    @Inject
    constructor(
        @ApplicationContext private val appContext: Context,
        private val apiCallManager: IApiCallManager,
        private val preferenceHelper: PreferencesHelper,
        private val firebaseManager: FirebaseManager,
        private val userRepository: UserRepository,
        private val employeeGate: com.windscribe.vpn.accessgate.EmployeeGate,
    ) : ViewModel() {
        private var captchaRefreshJob: Job? = null
        private val _loginState = MutableStateFlow<LoginState>(LoginState.Idle)
        val loginState: StateFlow<LoginState> = _loginState.asStateFlow()

        private val _loginButtonEnabled = MutableStateFlow(false)
        val loginButtonEnabled: StateFlow<Boolean> = _loginButtonEnabled.asStateFlow()

        private val _twoFactorEnabled = MutableStateFlow(false)
        val twoFactorEnabled: StateFlow<Boolean> = _twoFactorEnabled.asStateFlow()

        private val _selectedAuthType = MutableStateFlow(AuthType.STANDARD)
        val selectedAuthType: StateFlow<AuthType> = _selectedAuthType.asStateFlow()

        private val _accountHashDisplay = MutableStateFlow("")
        val accountHashDisplay: StateFlow<String> = _accountHashDisplay.asStateFlow()

        private val _triggerFilePicker = MutableSharedFlow<Boolean>(replay = 0)
        val triggerFilePicker: SharedFlow<Boolean> = _triggerFilePicker

        private val _showAllBackupFailedDialog = MutableSharedFlow<Boolean>(replay = 0)

        val showAllBackupFailedDialog: SharedFlow<Boolean> = _showAllBackupFailedDialog

        private val _showTwoFactorInfoDialog = MutableStateFlow(false)
        val showTwoFactorInfoDialog: StateFlow<Boolean> = _showTwoFactorInfoDialog.asStateFlow()

        private var username = ""
        private var wsUsername = ""
        private var wsPassword = ""
        private val _employeeSecondFactor = MutableStateFlow(false)
        val employeeSecondFactor: StateFlow<Boolean> = _employeeSecondFactor.asStateFlow()
        private var password = ""
        private var twoFactorCode = ""
        private var accountHash = ""
        private val logger = LoggerFactory.getLogger("LoginScreen")

        fun onUsernameChanged(username: String) {
            this.username = username
            validateInput()
        }

        fun onPasswordChanged(password: String) {
            this.password = password
            validateInput()
        }

        fun onTwoFactorChanged(twoFactorCode: String) {
            this.twoFactorCode = twoFactorCode
        }

        fun onAuthTypeChanged(authType: AuthType) {
            if (authType != AuthType.STANDARD) return
            viewModelScope.launch {
                _selectedAuthType.emit(authType)
                updateState(LoginState.Idle)
                _loginButtonEnabled.emit(false)
                if (authType == AuthType.STANDARD) {
                    validateInput()
                } else {
                    validateHashedInput()
                }
            }
        }

        fun onAccountHashChanged(hash: String) {
            val trimmedHash = hash.trim()
            this.accountHash = trimmedHash
            viewModelScope.launch {
                _accountHashDisplay.emit(trimmedHash)
            }
            validateHashedInput()
        }

        private fun validateHashedInput() {
            viewModelScope.launch {
                updateState(LoginState.Idle)
                _loginButtonEnabled.emit(accountHash.length >= 2)
            }
        }

        fun onCaptchaSolutionReceived(solution: CaptchaSolution) {
            viewModelScope.launch(Dispatchers.IO) {
                updateState(LoginState.LoggingIn("Logging in..."))
                _loginButtonEnabled.emit(false)
                loginWithCaptcha(solution)
            }
        }

        fun dismissCaptcha() {
            updateState(LoginState.Idle)
            validateInput()
        }

        /** Asks the API for a fresh challenge, keeping any error already shown to the user. */
        fun refreshCaptcha(error: String? = null) {
            if (captchaRefreshJob?.isActive == true) {
                return
            }
            captchaRefreshJob =
                viewModelScope.launch(Dispatchers.IO) {
                    // Marks the challenge on screen as stale so the dialog can show and announce
                    // that a new one is on its way.
                    (_loginState.value as? LoginState.Captcha)?.let {
                        updateState(it.copy(error = error, refreshing = true))
                    }
                    startLoginProcess(captchaError = error)
                }
        }

        fun onTwoFactorHintClicked() {
            viewModelScope.launch {
                _showTwoFactorInfoDialog.emit(true)
            }
        }

        fun dismissTwoFactorInfoDialog() {
            viewModelScope.launch {
                _showTwoFactorInfoDialog.emit(false)
            }
        }

        fun onUploadHashClick() {
            viewModelScope.launch {
                _triggerFilePicker.emit(true)
            }
        }

        fun onFileSelected(
            context: Context,
            uri: Uri,
        ) {
            viewModelScope.launch(Dispatchers.IO) {
                try {
                    val inputStream = context.contentResolver.openInputStream(uri)
                    if (inputStream != null) {
                        val hash = HashUtils.sha256FromInputStream(inputStream)
                        accountHash = hash
                        withContext(Dispatchers.Main) {
                            _accountHashDisplay.emit(hash)
                            validateHashedInput()
                        }
                        logger.info("Generated hash from file: ${hash.take(20)}...")
                    } else {
                        logger.error("Failed to open input stream for file")
                    }
                } catch (e: Exception) {
                    logger.error("Error hashing file: ${e.message}")
                }
            }
        }

        fun loginButtonClick() {
            if (_loginState.value is LoginState.LoggingIn) return

            viewModelScope.launch {
                updateState(LoginState.LoggingIn("Logging in..."))
                _loginButtonEnabled.emit(false)

                if (!WindUtilities.isOnline()) {
                    logger.info("User is not connected to the internet.")
                    _loginButtonEnabled.emit(true)
                    updateState(LoginState.Error(AuthError.LocalizedInputError(com.windscribe.vpn.R.string.no_internet)))
                    return@launch
                }

                try {
                    if (!employeeGate.hasPending()) {
                        val credentials = employeeGate.login(username.trim(), password)
                        wsUsername = credentials.first
                        wsPassword = credentials.second
                        password = ""
                        _employeeSecondFactor.value = true
                        _loginButtonEnabled.value = true
                        updateState(LoginState.Idle)
                    } else {
                        startLoginProcess()
                    }
                } catch (cancel: kotlinx.coroutines.CancellationException) {
                    throw cancel
                } catch (_: Exception) {
                    employeeGate.clear()
                    wsUsername = ""; wsPassword = ""
                    _employeeSecondFactor.value = false
                    _loginButtonEnabled.value = true
                    updateState(LoginState.Error(AuthError.InputError("Employee login failed. Check credentials, access and network.")))
                }
            }
        }

        private fun isValidUsername() = username.length >= 2

        private fun isValidPassword() = password.length >= 2

        private fun validateInput() {
            viewModelScope.launch {
                updateState(LoginState.Idle)
                _loginButtonEnabled.emit(
                    if (_employeeSecondFactor.value) employeeGate.hasPending() && wsUsername.isNotEmpty() && wsPassword.isNotEmpty()
                    else isValidUsername() && isValidPassword(),
                )
            }
        }

        private suspend fun loginWithCaptcha(captchaSolution: CaptchaSolution) {
            val trailX = captchaSolution.trail["x"]?.toFloatArray() ?: floatArrayOf()
            val trailY = captchaSolution.trail["y"]?.toFloatArray() ?: floatArrayOf()
            val result =
                result<UserLoginResponse> {
                    apiCallManager.logUserIn(
                        wsUsername,
                        wsPassword,
                        twoFactorCode.trim(),
                        captchaSolution.token,
                        captchaSolution.solution,
                        trailX,
                        trailY,
                    )
                }
            when (result) {
                is CallResult.Error -> {
                    val networkError = getNetworkError(result.code)
                    if (networkError != null) {
                        handleNetworkError(networkError)
                    } else if (result.code == NetworkErrorCodes.ERROR_INVALID_CAPTCHA) {
                        _loginButtonEnabled.emit(true)
                        startLoginProcess(
                            captchaError = SessionErrorHandler.instance.getErrorMessage(result.code, result.errorMessage),
                        )
                    } else {
                        _loginButtonEnabled.emit(true)
                        handleApiError(result.code, result.errorMessage)
                    }
                }

                is CallResult.Success -> {
                    logger.info("User signup in successfully.")
                    handleSuccessfulLogin(result.data.sessionAuthHash ?: "")
                }
            }
        }

        private suspend fun startLoginProcess(captchaError: String? = null) {
            logger.info("Trying to log in with provided credentials...")
            if (BuildConfig.DEV) {
                logger.info("DEV build: skipping auth-token step to bypass captcha for E2E tests.")
                handleAuthToken(AuthToken(token = "", captcha = null))
                return
            }
            val useTextCaptcha = AccessibilityHelper.isScreenReaderEnabled(appContext)
            if (useTextCaptcha) {
                logger.info("Screen reader detected, requesting text captcha.")
            }
            val authResult = result<AuthToken> { apiCallManager.authTokenLogin(wsUsername, useTextCaptcha) }
            when (authResult) {
                is CallResult.Error -> {
                    val networkError = getNetworkError(authResult.code)
                    if (networkError != null) {
                        handleNetworkError(networkError)
                    } else {
                        logger.info("Error login: ${authResult.errorMessage}")
                        _loginButtonEnabled.emit(true)
                        handleApiError(authResult.code, authResult.errorMessage)
                    }
                }

                is CallResult.Success -> {
                    logger.info("Received auth token successfully")
                    handleAuthToken(authResult.data, captchaError)
                }
            }
        }

        private suspend fun handleAuthToken(
            authToken: AuthToken,
            captchaError: String? = null,
        ) {
            val captcha = authToken.captcha
            val token = authToken.token
            if (captcha != null) {
                val request = captcha.toRequest(token)
                if (request == null) {
                    logger.warn("Captcha payload was missing the fields needed to render it.")
                    updateState(LoginState.Error(AuthError.LocalizedInputError(com.windscribe.vpn.R.string.captcha_unavailable)))
                    _loginButtonEnabled.emit(true)
                    return
                }
                logger.info("Received captcha: ${request::class.simpleName}")
                updateState(LoginState.Captcha(request, captchaError))
            } else {
                val result =
                    result<UserLoginResponse> {
                        apiCallManager.logUserIn(
                            wsUsername,
                            wsPassword,
                            twoFactorCode.trim(),
                            token,
                            null,
                            floatArrayOf(),
                            floatArrayOf(),
                        )
                    }
                when (result) {
                    is CallResult.Error -> {
                        val networkError = getNetworkError(result.code)
                        if (networkError != null) {
                            handleNetworkError(networkError)
                        } else {
                            logger.info("Error login: ${result.errorMessage}")
                            _loginButtonEnabled.emit(true)
                            handleApiError(result.code, result.errorMessage)
                        }
                    }

                    is CallResult.Success -> {
                        logger.info("User signup in successfully.")
                        handleSuccessfulLogin(result.data.sessionAuthHash ?: "")
                    }
                }
            }
        }

        private fun handleSuccessfulLogin(sessionAuthHash: String) {
            if (!employeeGate.completeLogin()) {
                preferenceHelper.sessionHash = null
                employeeGate.clear()
                wsUsername = ""; wsPassword = ""; twoFactorCode = ""
                _employeeSecondFactor.value = false
                _loginButtonEnabled.value = true
                updateState(LoginState.Error(AuthError.InputError("Employee access expired or secure storage failed.")))
                return
            }
            wsUsername = ""; wsPassword = ""; twoFactorCode = ""
            preferenceHelper.sessionHash = sessionAuthHash
            firebaseManager.getFirebaseToken { firebaseToken ->
                viewModelScope.launch(Dispatchers.IO) {
                    userRepository.prepareDashboard(firebaseToken).collect {
                        when (it) {
                            is UserDataState.Error -> {
                                preferenceHelper.sessionHash = null
                                employeeGate.clear()
                                _employeeSecondFactor.value = false
                                _loginButtonEnabled.value = true
                                updateState(
                                    LoginState.Error(
                                        AuthError.InputError(it.error),
                                    ),
                                )
                            }

                            is UserDataState.Loading -> {
                                updateState(LoginState.LoggingIn(it.status))
                            }

                            is UserDataState.Success -> {
                                updateState(LoginState.Success)
                            }
                        }
                    }
                }
            }
        }

        private fun handleNetworkError(failure: ApiFailure) {
            when (failure) {
                ApiFailure.AllFallbackFailed -> {
                    updateState(LoginState.Idle)
                    viewModelScope.launch {
                        _showAllBackupFailedDialog.emit(true)
                    }
                }

                ApiFailure.IncorrectJsonError -> {
                    updateState(LoginState.Error(AuthError.InputError("Incorrect JSON response received from server.")))
                }

                ApiFailure.Network -> {
                    updateState(LoginState.Error(AuthError.InputError("Network error, unable to connect to server.")))
                }

                ApiFailure.NoNetwork -> {
                    updateState(LoginState.Error(AuthError.LocalizedInputError(com.windscribe.vpn.R.string.no_internet)))
                }
            }
        }

        private suspend fun handleApiError(
            errorCode: Int,
            error: String,
        ) {
            logger.debug("Error code: $errorCode, Error: $error")
            val errorMessage = SessionErrorHandler.instance.getErrorMessage(errorCode, error)

            when (errorCode) {
                NetworkErrorCodes.ERROR_2FA_REQUIRED, NetworkErrorCodes.ERROR_INVALID_2FA -> {
                    _twoFactorEnabled.emit(true)
                    updateState(
                        LoginState.Error(
                            AuthError.InputError(
                                errorMessage,
                                listOf(AuthInputFields.TwoFactor),
                            ),
                        ),
                    )
                }

                else -> {
                    updateState(
                        LoginState.Error(
                            AuthError.InputError(
                                errorMessage,
                                listOf(AuthInputFields.Username, AuthInputFields.Password),
                            ),
                        ),
                    )
                }
            }
        }

        private fun updateState(state: LoginState) {
            viewModelScope.launch {
                _loginState.emit(state)
            }
        }

        fun clearDialog() {
            viewModelScope.launch {
                _showAllBackupFailedDialog.emit(false)
            }
        }

        override fun onCleared() {
            wsUsername = ""; wsPassword = ""; password = ""; twoFactorCode = ""
            if (employeeGate.hasPending()) employeeGate.clear()
            super.onCleared()
        }
    }
