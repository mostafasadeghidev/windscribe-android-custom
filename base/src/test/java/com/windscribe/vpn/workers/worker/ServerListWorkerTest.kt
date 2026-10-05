/*
 * Copyright (c) 2021 Windscribe Limited.
 */

package com.windscribe.vpn.workers.worker

import android.content.Context
import androidx.work.ListenableWorker.Result
import androidx.work.WorkerParameters
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.backend.utils.WindVpnController
import com.windscribe.vpn.repository.LocationRepository
import com.windscribe.vpn.repository.ServerListRepository
import com.windscribe.vpn.repository.UserRepository
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ServerListWorkerTest {
    private lateinit var context: Context
    private lateinit var workerParameters: WorkerParameters
    private lateinit var serverListRepository: ServerListRepository
    private lateinit var userRepository: UserRepository
    private lateinit var locationRepository: LocationRepository
    private lateinit var preferences: PreferencesHelper
    private lateinit var vpnController: WindVpnController

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        workerParameters = mockk(relaxed = true)
        serverListRepository = mockk(relaxed = true)
        userRepository = mockk(relaxed = true)
        locationRepository = mockk(relaxed = true)
        preferences = mockk(relaxed = true)
        vpnController = mockk(relaxed = true)
    }

    private fun TestScope.worker(): ServerListWorker =
        ServerListWorker(
            context,
            workerParameters,
            serverListRepository,
            userRepository,
            locationRepository,
            preferences,
            vpnController,
            this,
        )

    @Test
    fun `refresh reconnects when current node is no longer eligible`() =
        runTest {
            every { userRepository.loggedIn() } returns true
            coEvery { serverListRepository.update() } just Runs
            every { locationRepository.selectedCity } returns MutableStateFlow(7)
            coEvery { locationRepository.updateLocation() } returns 7
            coEvery { locationRepository.isNodeAvailable() } returns false
            every { preferences.globalUserConnectionPreference } returns true

            val result = worker().doWork()
            advanceUntilIdle()

            assertEquals(Result.success(), result)
            coVerify(exactly = 1) { serverListRepository.update() }
            verify(exactly = 1) { vpnController.connectAsync() }
        }

    @Test
    fun `refresh does not reconnect when current node remains eligible`() =
        runTest {
            every { userRepository.loggedIn() } returns true
            coEvery { serverListRepository.update() } just Runs
            every { locationRepository.selectedCity } returns MutableStateFlow(7)
            coEvery { locationRepository.updateLocation() } returns 7
            coEvery { locationRepository.isNodeAvailable() } returns true
            every { preferences.globalUserConnectionPreference } returns true

            val result = worker().doWork()
            advanceUntilIdle()

            assertEquals(Result.success(), result)
            coVerify(exactly = 1) { serverListRepository.update() }
            verify(exactly = 0) { vpnController.connectAsync() }
        }
}
