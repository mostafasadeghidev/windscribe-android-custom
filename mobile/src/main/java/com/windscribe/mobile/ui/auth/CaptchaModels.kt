package com.windscribe.mobile.ui.auth

import com.windscribe.vpn.api.response.Captcha

sealed class CaptchaRequest {
    abstract val secureToken: String

    /** Drag-a-piece-into-the-gap challenge. Needs sight to aim and a drag gesture to solve. */
    data class Puzzle(
        val background: String,
        val top: Int,
        val slider: String,
        override val secureToken: String,
    ) : CaptchaRequest()

    /**
     * Type-the-code challenge. Solved through a text field, so it carries no drag trail and can be
     * completed with a screen reader driving the UI.
     */
    data class Text(
        val asciiArt: String,
        override val secureToken: String,
    ) : CaptchaRequest()
}

data class CaptchaSolution(
    /** Left offset of the puzzle piece, or the code typed for a [CaptchaRequest.Text]. */
    val solution: String,
    val token: String,
    val trail: Map<String, List<Float>> = emptyMap(),
)

/**
 * Maps an API captcha payload onto the challenge it actually describes. Returns null when the
 * payload is missing the fields its own type needs, so callers can fall back instead of crashing.
 */
fun Captcha.toRequest(secureToken: String): CaptchaRequest? {
    asciiArt?.takeIf { it.isNotBlank() }?.let { art ->
        return CaptchaRequest.Text(art, secureToken)
    }
    val background = background ?: return null
    val slider = slider ?: return null
    val top = top ?: return null
    return CaptchaRequest.Puzzle(background, top, slider, secureToken)
}
