/*
 * Copyright (c) 2021 Windscribe Limited.
 */

package com.windscribe.vpn.api.response

import androidx.annotation.Keep
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName

/**
 * Server inventory delta response returned inline with GET /Session
 * when inv_rev parameter is supplied
 */
@Keep
data class ServerInventory(
    @SerializedName("action")
    @Expose
    val action: String, // "delta" or "hold"
    @SerializedName("enabled")
    @Expose
    val enabled: List<ServerData>?,
    @SerializedName("disabled")
    @Expose
    val disabled: List<DisabledServer>?,
    @SerializedName("revision")
    @Expose
    val revision: Long,
    @SerializedName("amneziawg_config_id")
    @Expose
    var amneziaWgConfigId: String? = null,
) {
    /**
     * True when this response carries node changes that have not been applied locally yet. The API
     * keeps returning the same delta until the client reports the matching revision, so it is safe
     * to use this to kick off a server list update.
     */
    fun hasPendingDelta(): Boolean = action == ACTION_DELTA && (enabled?.isNotEmpty() == true || disabled?.isNotEmpty() == true)

    companion object {
        const val ACTION_DELTA = "delta"
        const val ACTION_HOLD = "hold"
    }
}

@Keep
data class DisabledServer(
    @SerializedName("id")
    @Expose
    val id: Int,
)
