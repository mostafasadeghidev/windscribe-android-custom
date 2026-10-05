/*
 * Copyright (c) 2021 Windscribe Limited.
 */

package com.windscribe.vpn.workers.worker

import android.content.Context
import androidx.work.WorkerParameters
import com.windscribe.vpn.api.IApiCallManager
import com.windscribe.vpn.api.response.GenericResponseClass
import com.windscribe.vpn.api.response.ServerData
import com.windscribe.vpn.api.response.ServerInventory
import com.windscribe.vpn.api.response.UserSessionResponse
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.utils.WindVpnController
import com.windscribe.vpn.localdatabase.LocalDbInterface
import com.windscribe.vpn.model.User
import com.windscribe.vpn.repository.LocationRepository
import com.windscribe.vpn.repository.UserRepository
import com.windscribe.vpn.repository.WgConfigRepository
import com.windscribe.vpn.state.VPNConnectionStateManager
import com.windscribe.vpn.workers.WindScribeWorkManager
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test

class SessionWorkerForceDisconnectTest {
    private lateinit var context: Context
    private lateinit var workerParameters: WorkerParameters
    private lateinit var preferences: PreferencesHelper
    private lateinit var userRepository: UserRepository
    private lateinit var apiCallManager: IApiCallManager
    private lateinit var workManager: WindScribeWorkManager
    private lateinit var localDb: LocalDbInterface
    private lateinit var locationRepository: LocationRepository
    private lateinit var wgConfigRepository: WgConfigRepository
    private lateinit var vpnController: WindVpnController
    private lateinit var vpnStateManager: VPNConnectionStateManager

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        workerParameters = mockk(relaxed = true)
        preferences = mockk(relaxed = true)
        userRepository = mockk(relaxed = true)
        apiCallManager = mockk(relaxed = true)
        workManager = mockk(relaxed = true)
        localDb = mockk(relaxed = true)
        locationRepository = mockk(relaxed = true)
        wgConfigRepository = mockk(relaxed = true)
        vpnController = mockk(relaxed = true)
        vpnStateManager = mockk(relaxed = true)
        every { vpnStateManager.state } returns MutableStateFlow(VPNState(VPNState.Status.Disconnected))
    }

    private fun node(forceDisconnect: Int): ServerData =
        ServerData(
            id = 11,
            hostname = "sea-001.example",
            ip = "192.0.2.1",
            ip2 = "198.51.100.1",
            ip3 = "203.0.113.1",
            datacenterId = 7,
            weight = 1,
            health = 10,
            forceDisconnect = forceDisconnect,
        )

    private fun session(inventory: ServerInventory): UserSessionResponse =
        UserSessionResponse().apply {
            userName = "test-user"
            userAccountStatus = 1
            isPremium = 1
            serverInventory = inventory
        }

    private fun buildWorker(): SessionWorker =
        SessionWorker(
            context,
            workerParameters,
            preferences,
            userRepository,
            apiCallManager,
            workManager,
            localDb,
            locationRepository,
            wgConfigRepository,
            vpnController,
            vpnStateManager,
        )

    private fun arrangeSession(response: UserSessionResponse) {
        every { userRepository.loggedIn() } returns true
        every { userRepository.whatChanged(response) } returns listOf(false, false, false, false, false)
        coEvery { apiCallManager.getSessionGeneric(null, any()) } returns GenericResponseClass(response, null)
        coEvery { localDb.getAllStaticRegions() } returns emptyList()
        every { userRepository.reload(response, any()) } answers {
            val callback = secondArg<(suspend (User) -> Unit)?>()
            runBlocking {
                callback?.invoke(User(response))
            }
        }
    }

    @Test
    fun `pending force disconnect delta schedules server list refresh`() =
        runTest {
            val response =
                session(
                    ServerInventory(
                        action = ServerInventory.ACTION_DELTA,
                        enabled = listOf(node(forceDisconnect = 1)),
                        disabled = emptyList(),
                        revision = 43,
                    ),
                )
            arrangeSession(response)

            val result = buildWorker().doWork()

            assertNotNull(result.outputData.getString("data"))
            verify(exactly = 1) { workManager.updateServerList() }
        }

    @Test
    fun `empty delta does not schedule server list refresh`() =
        runTest {
            val response =
                session(
                    ServerInventory(
                        action = ServerInventory.ACTION_DELTA,
                        enabled = emptyList(),
                        disabled = emptyList(),
                        revision = 43,
                    ),
                )
            arrangeSession(response)

            val result = buildWorker().doWork()

            assertNotNull(result.outputData.getString("data"))
            verify(exactly = 0) { workManager.updateServerList() }
        }
}
