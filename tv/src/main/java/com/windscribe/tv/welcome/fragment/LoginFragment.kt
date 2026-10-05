/*
 * Copyright (c) 2021 Windscribe Limited.
 */
package com.windscribe.tv.welcome.fragment

import android.content.Context
import android.content.res.ColorStateList
import android.os.Bundle
import android.text.method.PasswordTransformationMethod
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.windscribe.tv.R
import com.windscribe.tv.databinding.FragmentLoginBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.windscribe.vpn.R as BaseR

class LoginFragment :
    Fragment(),
    WelcomeActivityCallback {
    private lateinit var generateCode: Button
    private lateinit var manualLoginContainer: View
    private lateinit var qrCode: ImageView
    private lateinit var qrLoginContainer: View
    private lateinit var qrLoading: View
    private lateinit var qrErrorContainer: View
    private lateinit var qrErrorMessage: TextView
    private lateinit var qrRetryButton: Button
    private lateinit var secretCode: TextView
    private lateinit var secretCodeLarge: TextView
    private lateinit var binding: FragmentLoginBinding
    private var callBack: FragmentCallback? = null
    private var currentQrBitmap: android.graphics.Bitmap? = null

    override fun onAttach(context: Context) {
        if (activity is FragmentCallback) {
            callBack = activity as FragmentCallback?
        }
        super.onAttach(context)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        binding = FragmentLoginBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(
        view: View,
        savedInstanceState: Bundle?,
    ) {
        super.onViewCreated(view, savedInstanceState)
        generateCode = view.findViewById(R.id.generate_code)
        manualLoginContainer = view.findViewById(R.id.manual_login_container)
        qrCode = view.findViewById(R.id.qr_code)
        qrLoginContainer = view.findViewById(R.id.qr_login_container)
        qrLoading = view.findViewById(R.id.qr_loading)
        qrErrorContainer = view.findViewById(R.id.qr_error_container)
        qrErrorMessage = view.findViewById(R.id.qr_error_message)
        qrRetryButton = view.findViewById(R.id.qr_retry_button)
        secretCode = view.findViewById(R.id.secret_code)
        secretCodeLarge = view.findViewById(R.id.secret_code_large)
        binding.loginSignUpContainer.requestFocus()
        binding.passwordEdit.transformationMethod = PasswordTransformationMethod()
        binding.showPassword.isChecked = false
        addFocusListeners()
        addClickListeners()
        clearInputErrors()
    }

    private fun addFocusListeners() {
        arrayOf(binding.usernameEdit, binding.passwordEdit).forEach {
            it.setOnFocusChangeListener { _, _ ->
                clearInputErrors()
            }
        }
        arrayOf(
            binding.back,
            binding.forgotPassword,
            binding.passwordContainer,
            binding.showPassword,
            binding.usernameContainer,
            binding.loginSignUp,
            generateCode,
        ).forEach {
            it.setOnFocusChangeListener { _, _ ->
                resetButtonTextColor()
            }
        }
    }

    private fun addClickListeners() {
        binding.back.setOnClickListener {
            callBack?.onBackButtonPressed()
        }
        binding.forgotPassword.setOnClickListener {
            callBack?.onForgotPasswordClick()
        }
        generateCode.setOnClickListener {
            callBack?.onGenerateCodeClick()
        }
        qrRetryButton.setOnClickListener {
            secretCode.text?.toString()?.let { code ->
                if (code.isNotEmpty()) {
                    generateQrCode(code)
                }
            }
        }
        binding.loginSignUp.setOnClickListener {
            callBack?.onAuthLoginClick(binding.usernameEdit.text.toString(), binding.passwordEdit.text.toString())
        }
        binding.passwordContainer.setOnClickListener {
            binding.showPassword.visibility = View.VISIBLE
            binding.passwordEdit.visibility = View.VISIBLE
            binding.passwordEdit.requestFocus()
        }
        binding.showPassword.setOnClickListener {
            if (binding.showPassword.isChecked) {
                binding.passwordEdit.transformationMethod = null
            } else {
                binding.passwordEdit.transformationMethod = PasswordTransformationMethod()
            }
            binding.passwordEdit.setSelection(binding.passwordEdit.text?.length ?: 0)
        }
        binding.usernameContainer.setOnClickListener {
            binding.usernameEdit.visibility = View.VISIBLE
            binding.usernameEdit.requestFocus()
        }
    }

    override fun clearInputErrors() {
        binding.error.visibility = View.INVISIBLE
        binding.error.text = ""
    }

    private fun recycleQrBitmap() {
        currentQrBitmap?.let {
            if (!it.isRecycled) {
                it.recycle()
            }
        }
        currentQrBitmap = null
    }

    override fun setLoginError(error: String) {
        binding.error.visibility = View.VISIBLE
        binding.error.text = error
    }

    override fun setPasswordError(error: String) {
        binding.error.visibility = View.VISIBLE
        binding.error.text = error
    }

    override fun setSecretCode(code: String) {
        if (code.isEmpty()) {
            secretCode.text = code
            secretCodeLarge.text = code
            recycleQrBitmap()
            qrCode.setImageDrawable(null)
            // Reset all QR states
            qrLoading.visibility = View.GONE
            qrErrorContainer.visibility = View.GONE
            qrCode.visibility = View.VISIBLE
            qrLoginContainer.visibility = View.GONE
            manualLoginContainer.visibility = View.VISIBLE
            generateCode.requestFocus()
        } else {
            secretCode.text = code
            secretCodeLarge.text = code
            manualLoginContainer.visibility = View.GONE
            qrLoginContainer.visibility = View.VISIBLE
            binding.usernameContainer.requestFocus()
            generateQrCode(code)
        }
    }

    private fun generateQrCode(code: String) {
        qrCode.post {
            if (!isAdded || secretCode.text.toString() != code) return@post
            val width = qrCode.width - qrCode.paddingLeft - qrCode.paddingRight
            val height = qrCode.height - qrCode.paddingTop - qrCode.paddingBottom
            if (width <= 0 || height <= 0) return@post
            showQrLoading()
            viewLifecycleOwner.lifecycleScope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        LazyLoginQrCode.bitmap(
                            LazyLoginQrCode.loginUrl(code),
                            width,
                            height,
                        )
                    }
                }.onSuccess { bitmap ->
                    // Set bitmap on main thread
                    if (isAdded && secretCode.text.toString() == code) {
                        // Recycle previous bitmap before setting new one
                        recycleQrBitmap()
                        currentQrBitmap = bitmap
                        qrCode.setImageBitmap(bitmap)
                        showQrSuccess()
                    } else {
                        // If fragment is not attached or code has changed, recycle the bitmap
                        bitmap.recycle()
                    }
                }.onFailure { error ->
                    // Show error state with user feedback
                    if (isAdded && secretCode.text.toString() == code) {
                        showQrError(error.message ?: getString(BaseR.string.qr_generation_failed))
                    }
                }
            }
        }
    }

    private fun showQrLoading() {
        qrLoading.visibility = View.VISIBLE
        qrErrorContainer.visibility = View.GONE
        qrCode.visibility = View.INVISIBLE
    }

    private fun showQrSuccess() {
        qrLoading.visibility = View.GONE
        qrErrorContainer.visibility = View.GONE
        qrCode.visibility = View.VISIBLE
    }

    private fun showQrError(message: String) {
        qrLoading.visibility = View.GONE
        qrErrorContainer.visibility = View.VISIBLE
        qrCode.visibility = View.INVISIBLE
        qrErrorMessage.text = message
        qrRetryButton.requestFocus()
    }

    override fun setUsernameError(error: String) {
        binding.error.visibility = View.VISIBLE
        binding.error.text = error
    }

    private fun resetButtonTextColor() {
        val normalColor = requireActivity().resources.getColor(R.color.colorWhite50)
        val focusColor = requireActivity().resources.getColor(R.color.colorWhite)
        binding.loginSignUp.setTextColor(
            if (binding.loginSignUp.hasFocus()) {
                requireActivity().resources.getColor(R.color.colorWhite)
            } else {
                requireActivity().resources.getColor(
                    R.color.colorWhite50,
                )
            },
        )
        generateCode.setTextColor(
            if (generateCode.hasFocus()) {
                requireActivity().resources.getColor(R.color.colorWhite)
            } else {
                requireActivity().resources.getColor(
                    R.color.colorWhite50,
                )
            },
        )
        binding.back.setTextColor(if (binding.back.hasFocus()) focusColor else normalColor)
        binding.forgotPassword.setTextColor(if (binding.forgotPassword.hasFocus()) focusColor else normalColor)
        binding.showPassword.setTextColor(if (binding.showPassword.hasFocus()) focusColor else normalColor)
        binding.showPassword.buttonTintList =
            ColorStateList.valueOf(if (binding.showPassword.hasFocus()) focusColor else normalColor)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        recycleQrBitmap()
    }
}
