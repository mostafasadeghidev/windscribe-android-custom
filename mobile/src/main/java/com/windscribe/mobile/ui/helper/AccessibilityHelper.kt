package com.windscribe.mobile.ui.helper

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager

object AccessibilityHelper {
    fun isScreenReaderEnabled(context: Context): Boolean {
        val manager =
            context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
                ?: return false
        if (!manager.isEnabled) {
            return false
        }
        if (manager.isTouchExplorationEnabled) {
            return true
        }
        // Braille displays and external keyboard users may not have touch exploration on, but
        // requiring the capability keeps services that only speak - Voice Access, OEM assistants -
        // on the puzzle challenge.
        val feedbackTypes =
            AccessibilityServiceInfo.FEEDBACK_SPOKEN or AccessibilityServiceInfo.FEEDBACK_BRAILLE
        return manager.getEnabledAccessibilityServiceList(feedbackTypes).any {
            it.capabilities and
                AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_TOUCH_EXPLORATION != 0
        }
    }
}
