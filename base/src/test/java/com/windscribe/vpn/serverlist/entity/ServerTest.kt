/*
 * Copyright (c) 2021 Windscribe Limited.
 */

package com.windscribe.vpn.serverlist.entity

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerTest {
    private fun server(forceDisconnect: Int): Server =
        Server(
            id = 1,
            hostname = "sea-001.windscribe.com",
            ip = "10.0.0.1",
            ip2 = "10.0.0.2",
            ip3 = "10.0.0.3",
            datacenterId = 7,
            weight = 5,
            health = 20,
            forceDisconnect = forceDisconnect,
        )

    @Test
    fun `node flagged for force disconnect is not a connection candidate`() {
        assertFalse(server(forceDisconnect = 1).isConnectable)
    }

    @Test
    fun `node without force disconnect flag is a connection candidate`() {
        assertTrue(server(forceDisconnect = 0).isConnectable)
    }
}
