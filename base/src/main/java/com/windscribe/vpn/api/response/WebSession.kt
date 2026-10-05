/*
 * Copyright (c) 2021 Windscribe Limited.
 */

package com.windscribe.vpn.api.response

import androidx.annotation.Keep
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName

@Keep
class WebSession {
    @SerializedName("temp_session")
    @Expose
    val tempSession: String? = null

    // tempSession is a live bearer token for the account's web dashboard, so it is redacted here
    // the same way SsoResponse redacts sessionAuth: the debug log is uploadable and shareable, and
    // a single logger call on this object would otherwise put the credential in it.
    override fun toString(): String = "WebSession{tempSession='[REDACTED]'}"
}
