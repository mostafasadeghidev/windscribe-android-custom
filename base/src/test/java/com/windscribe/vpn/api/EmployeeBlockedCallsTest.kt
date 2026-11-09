package com.windscribe.vpn.api

import com.windscribe.vpn.wsnet.WSNetWrapper
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Calls that would change the shared account or sign another device in never leave the app. */
class EmployeeBlockedCallsTest {
    // Strict: any call into wsnet throws and fails the test.
    private val wsnet = mockk<WSNetWrapper>()
    private val api = ApiCallManager(wsnet, mockk(relaxed = true), mockk(relaxed = true))

    private fun assertBlocked(response: com.windscribe.vpn.api.response.GenericResponseClass<*, *>) {
        assertNull(response.dataClass)
        val error = response.errorClass as com.windscribe.vpn.api.response.ApiErrorResponse
        assertEquals(EMPLOYEE_BLOCKED, error.errorCode)
    }

    @Test
    fun `account calls are refused without reaching the server`() =
        runTest {
            assertBlocked(api.getWebSession())
            assertBlocked(api.verifyExpressLoginCode("ABCDEF"))
            assertBlocked(api.generateXPressLoginCode())
            assertBlocked(api.claimVoucherCode("CODE"))
            assertBlocked(api.addUserEmailAddress("someone@example.com"))
            assertBlocked(api.resendUserEmailAddress())
            assertBlocked(api.passwordRecovery("someone@example.com"))
            assertBlocked(api.loginWithCode("CODE"))
        }
}
