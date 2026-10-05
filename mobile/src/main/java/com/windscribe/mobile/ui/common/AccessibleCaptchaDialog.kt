package com.windscribe.mobile.ui.common

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.windscribe.mobile.ui.auth.CaptchaRequest
import com.windscribe.mobile.ui.auth.CaptchaSolution
import com.windscribe.mobile.ui.theme.AppColors
import com.windscribe.mobile.ui.theme.font12
import com.windscribe.mobile.ui.theme.font18

/** Height budget for the art block, so tall art cannot push the input off screen. */
private const val ASCII_MAX_HEIGHT = 220

/**
 * Text based CAPTCHA, shown in place of the drag puzzle when a screen reader is active.
 *
 * Everything here is reachable with a single linear focus order and solved by typing, so it never
 * asks for the spatial drag trail the puzzle challenge depends on.
 */
@Composable
fun AccessibleCaptchaDialog(
    request: CaptchaRequest.Text,
    error: String?,
    refreshing: Boolean = false,
    onCancel: () -> Unit,
    onRefresh: () -> Unit,
    onSolutionSubmit: (CaptchaSolution) -> Unit,
) {
    val title = stringResource(com.windscribe.vpn.R.string.complete_puzzle_to_continue)
    Dialog(
        onDismissRequest = onCancel,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = AppColors.charcoalBlue,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .semantics { paneTitle = title },
            border = BorderStroke(1.dp, AppColors.white.copy(alpha = 0.05f)),
            tonalElevation = 8.dp,
        ) {
            AccessibleCaptchaContent(request, error, refreshing, onCancel, onRefresh, onSolutionSubmit)
        }
    }
}

@Composable
private fun AccessibleCaptchaContent(
    request: CaptchaRequest.Text,
    error: String?,
    refreshing: Boolean,
    onCancel: () -> Unit,
    onRefresh: () -> Unit,
    onSolutionSubmit: (CaptchaSolution) -> Unit,
) {
    val art = remember(request.asciiArt) { decodeBase64ToText(request.asciiArt) }
    var solution by remember(request.secureToken) { mutableStateOf("") }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(24.dp),
    ) {
        Text(
            text = stringResource(com.windscribe.vpn.R.string.complete_puzzle_to_continue),
            color = AppColors.white,
            style = font18.copy(fontWeight = FontWeight.Medium),
            modifier = Modifier.semantics { heading() },
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(com.windscribe.vpn.R.string.captcha_enter_code),
            style = font12.copy(fontWeight = FontWeight.Normal),
            textAlign = TextAlign.Center,
            color = AppColors.white.copy(alpha = 0.50f),
        )
        Spacer(modifier = Modifier.height(24.dp))

        if (art == null) {
            Text(
                text = stringResource(com.windscribe.vpn.R.string.captcha_unavailable),
                style = font12,
                color = AppColors.red,
            )
        } else {
            // Dimmed while a new challenge is in flight, so the stale code does not read as current.
            AsciiArt(art, modifier = Modifier.alpha(if (refreshing) 0.3f else 1f))
        }

        if (refreshing) {
            Spacer(modifier = Modifier.height(16.dp))
            RefreshingStatus()
        }

        if (error != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = error,
                style = font12,
                color = AppColors.red,
                textAlign = TextAlign.Center,
                // Announced by the screen reader as soon as a failed attempt comes back.
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
            )
        }

        Spacer(modifier = Modifier.height(24.dp))
        // Keyed on the token so a refreshed challenge starts with an empty field.
        key(request.secureToken) {
            AuthTextField(
                modifier = Modifier.fillMaxWidth(),
                hint = stringResource(com.windscribe.vpn.R.string.captcha_code_hint),
                isError = error != null,
                onValueChange = { solution = it },
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
        NextButtonLighterNoPadding(
            modifier = Modifier.fillMaxWidth(),
            text = stringResource(com.windscribe.vpn.R.string.captcha_verify),
            enabled = !refreshing,
        ) {
            if (solution.isNotBlank()) {
                onSolutionSubmit(CaptchaSolution(solution.trim(), request.secureToken))
            }
        }
        Spacer(modifier = Modifier.height(12.dp))
        NextButtonLighterNoPadding(
            modifier = Modifier.fillMaxWidth(),
            text = stringResource(com.windscribe.vpn.R.string.captcha_refresh),
            enabled = !refreshing,
            onClick = onRefresh,
        )
        Spacer(modifier = Modifier.height(12.dp))
        NextButtonLighterNoPadding(
            modifier = Modifier.fillMaxWidth(),
            text = stringResource(com.windscribe.vpn.R.string.cancel),
            onClick = onCancel,
        )
    }
}

/** Announced as soon as a refresh starts, so the tap is not silent to a screen reader. */
@Composable
private fun RefreshingStatus() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(
            modifier = Modifier.size(16.dp),
            color = AppColors.white,
            strokeWidth = 2.dp,
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = stringResource(com.windscribe.vpn.R.string.captcha_refreshing),
            style = font12,
            color = AppColors.white.copy(alpha = 0.50f),
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
        )
    }
}

/**
 * Renders the challenge art.
 *
 * The payload is a monochrome bitmap that happens to be encoded as characters, so it is drawn as
 * one rather than laid out as text. Drawing it as text ties the cell size to the font's advance and
 * line height, which on this art works out near 1:2.5 and stretches a grid meant for square cells
 * until the glyphs stop reading. Square cells sized to fill the box keep the proportions the art was
 * drawn at.
 *
 * Reading the characters out one by one is noise, so the whole block is collapsed into a single
 * description for screen readers.
 */
@Composable
private fun AsciiArt(
    art: String,
    modifier: Modifier = Modifier,
) {
    val description = stringResource(com.windscribe.vpn.R.string.captcha_art_description)
    val rows =
        remember(art) {
            art
                .lines()
                .dropWhile { it.isBlank() }
                .dropLastWhile { it.isBlank() }
        }
    val columns = remember(rows) { rows.maxOfOrNull { it.length } ?: 0 }

    BoxWithConstraints(
        modifier =
            modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(AppColors.white.copy(alpha = 0.05f))
                .padding(horizontal = 12.dp, vertical = 16.dp)
                .clearAndSetSemantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) {
        if (rows.isEmpty() || columns == 0) {
            return@BoxWithConstraints
        }
        val cell = minOf(maxWidth / columns, ASCII_MAX_HEIGHT.dp / rows.size)
        val ink = AppColors.white
        Canvas(modifier = Modifier.size(cell * columns, cell * rows.size)) {
            val cellPx = cell.toPx()
            rows.forEachIndexed { y, line ->
                // Each run of set cells is one rect, so no anti-aliased seams show up between them.
                forEachRun(line) { startX, endX ->
                    drawRect(
                        color = ink,
                        topLeft = Offset(startX * cellPx, y * cellPx),
                        size = Size((endX - startX) * cellPx, cellPx),
                    )
                }
            }
        }
    }
}

/** Calls [onRun] with the half-open bounds of every run of set (non-blank) cells in [line]. */
internal inline fun forEachRun(
    line: String,
    onRun: (start: Int, end: Int) -> Unit,
) {
    var start = -1
    line.forEachIndexed { index, character ->
        if (character.isWhitespace()) {
            if (start >= 0) {
                onRun(start, index)
                start = -1
            }
        } else if (start < 0) {
            start = index
        }
    }
    if (start >= 0) {
        onRun(start, line.length)
    }
}

private fun decodeBase64ToText(base64: String): String? =
    try {
        String(android.util.Base64.decode(base64, android.util.Base64.DEFAULT), Charsets.UTF_8)
    } catch (e: IllegalArgumentException) {
        null
    }
