package com.windscribe.mobile.ui.auth

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.windscribe.mobile.ui.common.StyledTextFieldWithActions
import com.windscribe.mobile.ui.theme.AppColors
import com.windscribe.mobile.ui.theme.font16

@Composable
fun StandardLoginForm(
    modifier: Modifier = Modifier,
    employeeSecondFactor: Boolean = false,
    isUsernameError: Boolean = false,
    isPasswordError: Boolean = false,
    is2FAError: Boolean = false,
    onUsernameChange: (String) -> Unit = {},
    onPasswordChange: (String) -> Unit = {},
    on2FAChange: (String) -> Unit = {},
    on2FAInfoClick: () -> Unit = {},
) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(employeeSecondFactor) { password = "" }
    Column(modifier) {
        Text(if (employeeSecondFactor) "Windscribe two-factor code" else "Employee login", style = font16, color = AppColors.white)
        Spacer(Modifier.height(16.dp))
        if (!employeeSecondFactor) {
            StyledTextFieldWithActions(value = username, onValueChange = { username = it; onUsernameChange(it) }, placeholder = "Employee username", isError = isUsernameError, imeAction = ImeAction.Next)
            Spacer(Modifier.height(16.dp))
            StyledTextFieldWithActions(value = password, onValueChange = { password = it; onPasswordChange(it) }, placeholder = "Employee password", isError = isPasswordError, isPassword = true, passwordVisible = passwordVisible, onPasswordVisibilityToggle = { passwordVisible = !passwordVisible }, keyboardType = KeyboardType.Password, imeAction = ImeAction.Done)
        } else {
            StyledTextFieldWithActions(value = code, onValueChange = { code = it; on2FAChange(it) }, placeholder = "Two-factor code (leave blank if not required)", isError = is2FAError, keyboardType = KeyboardType.Number, imeAction = ImeAction.Done)
        }
    }
}
