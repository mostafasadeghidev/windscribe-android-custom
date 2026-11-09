package com.windscribe.vpn.backend

import com.windscribe.vpn.accessgate.EmployeeGate
import com.windscribe.vpn.apppreference.PreferencesKeyConstants.PROTO_WIRE_GUARD
import com.windscribe.vpn.autoconnection.ProtocolInformation
import com.windscribe.vpn.backend.wireguard.WireguardBackend
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.UUID

/** Every connect path, including a late VPN permission grant, ends in [VpnBackendHolder.connect]. */
@OptIn(ExperimentalCoroutinesApi::class)
class VpnBackendHolderEmployeeGateTest {
    private val wireguard = mockk<WireguardBackend>(relaxed = true)
    private val gate = mockk<EmployeeGate>()
    private val protocol = mockk<ProtocolInformation> { every { this@mockk.protocol } returns PROTO_WIRE_GUARD }

    private fun kotlinx.coroutines.CoroutineScope.holder() =
        VpnBackendHolder(this, mockk(relaxed = true), mockk(relaxed = true), wireguard, mockk(relaxed = true), gate)

    @Test
    fun `denied employee never reaches a backend`() =
        runTest {
            every { gate.isAllowed() } returns false
            val holder = holder()

            holder.connect(protocol, UUID.randomUUID())
            advanceUntilIdle()

            assertNull(holder.activeBackend)
            verify(exactly = 0) { wireguard.activate() }
            verify(exactly = 0) { wireguard.connect(any(), any()) }
        }

    @Test
    fun `allowed employee connects`() =
        runTest {
            every { gate.isAllowed() } returns true
            val id = UUID.randomUUID()

            holder().connect(protocol, id)
            advanceUntilIdle()

            verify { wireguard.activate() }
            verify { wireguard.connect(protocol, id) }
        }
}
