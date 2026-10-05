/*
 * Copyright (c) 2021 Windscribe Limited.
 */

package com.windscribe.vpn.api.response

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerResponseTest {
    private val gson = Gson()

    private fun node(extraFields: String): String =
        """
        {
          "id": 11,
          "host": "sea-001.windscribe.com",
          "ip": "10.0.0.1",
          "ip2": "10.0.0.2",
          "ip3": "10.0.0.3",
          "dc_id": 7,
          "weight": 5,
          "net_load": 20$extraFields
        }
        """.trimIndent()

    // ---------- fd on the full server list ----------

    @Test
    fun `server list node with fd 1 is parsed as force disconnect`() {
        val json = """{"servers": [${node(", \"fd\": 1")}], "revision": 42}"""

        val response = gson.fromJson(json, ServerResponse::class.java)

        assertEquals(1, response.servers.single().forceDisconnect)
    }

    @Test
    fun `server list node without fd defaults to not force disconnected`() {
        val json = """{"servers": [${node("")}], "revision": 42}"""

        val response = gson.fromJson(json, ServerResponse::class.java)

        assertEquals(0, response.servers.single().forceDisconnect)
    }

    // ---------- fd on the session inventory delta ----------

    @Test
    fun `inventory delta carries fd flag on enabled nodes`() {
        val json =
            """
            {
              "action": "delta",
              "enabled": [${node(", \"fd\": 1")}],
              "disabled": [],
              "revision": 43
            }
            """.trimIndent()

        val inventory = gson.fromJson(json, ServerInventory::class.java)

        assertEquals(1, inventory.enabled?.single()?.forceDisconnect)
    }

    // ---------- hasPendingDelta ----------

    @Test
    fun `hasPendingDelta is true when delta has enabled nodes`() {
        val json =
            """
            {"action": "delta", "enabled": [${node(", \"fd\": 1")}], "disabled": [], "revision": 43}
            """.trimIndent()

        assertTrue(gson.fromJson(json, ServerInventory::class.java).hasPendingDelta())
    }

    @Test
    fun `hasPendingDelta is true when delta only disables nodes`() {
        val json = """{"action": "delta", "enabled": [], "disabled": [{"id": 11}], "revision": 43}"""

        assertTrue(gson.fromJson(json, ServerInventory::class.java).hasPendingDelta())
    }

    @Test
    fun `hasPendingDelta is false for an empty delta`() {
        val json = """{"action": "delta", "enabled": [], "disabled": [], "revision": 43}"""

        assertFalse(gson.fromJson(json, ServerInventory::class.java).hasPendingDelta())
    }

    @Test
    fun `hasPendingDelta is false for hold`() {
        val json = """{"action": "hold", "revision": 43}"""

        assertFalse(gson.fromJson(json, ServerInventory::class.java).hasPendingDelta())
    }
}
