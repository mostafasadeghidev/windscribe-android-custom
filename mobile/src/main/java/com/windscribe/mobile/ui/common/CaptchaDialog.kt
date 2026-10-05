package com.windscribe.mobile.ui.common

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.windscribe.mobile.ui.auth.CaptchaRequest
import com.windscribe.mobile.ui.auth.CaptchaSolution
import com.windscribe.mobile.ui.theme.AppColors
import com.windscribe.mobile.ui.theme.font12
import com.windscribe.mobile.ui.theme.font18
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** Fraction of the puzzle width one accessibility nudge moves the piece. */
private const val NUDGE_FRACTION = 0.02f

@OptIn(ExperimentalEncodingApi::class)
private fun decodeBase64ToBitmap(base64: String): Bitmap? {
    try {
        val decodedBytes = Base64.decode(base64)
        val stream = ByteArrayInputStream(decodedBytes)
        return BitmapFactory.decodeStream(stream)
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return null
}

@Composable
fun PuzzleCaptchaDialog(
    captchaRequest: CaptchaRequest.Puzzle,
    error: String?,
    onCancel: () -> Unit,
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
                    .padding(16.dp)
                    .semantics { paneTitle = title },
            border = BorderStroke(1.dp, AppColors.white.copy(alpha = 0.05f)),
            tonalElevation = 8.dp,
        ) {
            PuzzleCaptchaView(captchaRequest, error, onSolutionSubmit, onCancel)
        }
    }
}

@Composable
fun PuzzleCaptchaView(
    captcha: CaptchaRequest.Puzzle,
    error: String?,
    onSolutionSubmit: (CaptchaSolution) -> Unit,
    onCancel: () -> Unit,
) {
    val captchaBackground = decodeBase64ToBitmap(captcha.background)
    val slider = decodeBase64ToBitmap(captcha.slider)

    if (captchaBackground == null || slider == null) {
        Text(
            text = stringResource(com.windscribe.vpn.R.string.captcha_unavailable),
            color = AppColors.red,
            modifier = Modifier.padding(24.dp),
        )
        return
    }

    val density = LocalDensity.current
    val configuration = LocalConfiguration.current

    // Calculate available width: screen width - total padding (16dp + 24dp on each side = 80dp total)
    val totalPaddingDp = 80.dp // 16dp (dialog) + 24dp (content) on each side
    val screenWidthDp = configuration.screenWidthDp.dp
    val availableWidthDp = screenWidthDp - totalPaddingDp
    val availableWidthPx = with(density) { availableWidthDp.toPx() }

    // Calculate image sizing
    val originalWidth = captchaBackground.width.toFloat()
    val originalHeight = captchaBackground.height.toFloat()
    val aspectRatio = originalWidth / originalHeight

    val (finalWidth, finalHeight, scaleFactor) =
        if (originalWidth > availableWidthPx) {
            // Image is larger than available space, resize to fit
            val newWidth = availableWidthPx
            val newHeight = newWidth / aspectRatio
            val scale = newWidth / originalWidth
            Triple(newWidth.toInt(), newHeight.toInt(), scale)
        } else {
            // Image fits, use original size
            Triple(originalWidth.toInt(), originalHeight.toInt(), 1f)
        }

    // Initialize slider position with scaling applied
    val sliderPositionX = remember { mutableFloatStateOf(0f) }
    val sliderPositionY = remember { mutableFloatStateOf(captcha.top.toFloat() * scaleFactor) }
    val initialY = remember { mutableFloatStateOf(captcha.top.toFloat()) }
    val dragHistory = remember { mutableStateListOf<Pair<Float, Float>>() }

    val backgroundSize = remember { mutableStateOf(IntSize(finalWidth, finalHeight)) }

    val backgroundBitmap = captchaBackground.asImageBitmap()
    val sliderBitmap = slider.asImageBitmap()
    val scaledSliderWidth = (slider.width * scaleFactor).toInt()
    val scaledSliderHeight = (slider.height * scaleFactor).toInt()
    val maxX = (backgroundSize.value.width - scaledSliderWidth).toFloat().coerceAtLeast(1f)

    fun submit() {
        // Convert scaled position back to original image coordinates for API
        val originalXOffset = sliderPositionX.floatValue / scaleFactor
        val xPositions = dragHistory.map { it.first / scaleFactor }
        val yPositions = dragHistory.map { it.second / scaleFactor }
        val trail = mapOf("x" to xPositions, "y" to yPositions)
        onSolutionSubmit(CaptchaSolution("$originalXOffset", captcha.secureToken, trail))
    }

    fun recordPoint(
        newX: Float,
        newY: Float,
    ) {
        val newPoint = Pair(newX, newY - (initialY.floatValue * scaleFactor))
        // Only add point if it's at least 0.5 pixels away from the last recorded point
        val shouldRecord =
            if (dragHistory.isEmpty()) {
                true
            } else {
                val lastPoint = dragHistory.last()
                val distance =
                    kotlin.math.sqrt(
                        (newPoint.first - lastPoint.first) * (newPoint.first - lastPoint.first) +
                            (newPoint.second - lastPoint.second) * (newPoint.second - lastPoint.second),
                    )
                distance >= 0.5f
            }

        if (shouldRecord) {
            dragHistory.add(newPoint)
            if (dragHistory.size > 50) {
                dragHistory.removeAt(0)
            }
        }
        sliderPositionX.floatValue = newX
        sliderPositionY.floatValue = newY
    }

    // Held in a state holder so the pending job survives the recomposition that recordPoint
    // triggers, otherwise none of the cancels below can reach it.
    val dragJob = remember { mutableStateOf<Job?>(null) }
    val coroutineScope = rememberCoroutineScope()

    fun scheduleSubmit() {
        dragJob.value?.cancel()
        dragJob.value =
            coroutineScope.launch {
                delay(700)
                submit()
            }
    }

    fun nudge(direction: Int): Boolean {
        val step = maxX * NUDGE_FRACTION
        recordPoint(
            (sliderPositionX.floatValue + (direction * step)).coerceIn(0f, maxX),
            sliderPositionY.floatValue,
        )
        scheduleSubmit()
        return true
    }

    val shape = RoundedCornerShape(8.dp)
    val puzzleDescription = stringResource(com.windscribe.vpn.R.string.captcha_puzzle_background)
    val pieceDescription = stringResource(com.windscribe.vpn.R.string.captcha_puzzle_piece)
    val moveLeftLabel = stringResource(com.windscribe.vpn.R.string.captcha_move_piece_left)
    val moveRightLabel = stringResource(com.windscribe.vpn.R.string.captcha_move_piece_right)
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier = Modifier.padding(top = 24.dp, start = 24.dp, end = 24.dp, bottom = 24.dp),
    ) {
        Text(
            stringResource(com.windscribe.vpn.R.string.complete_puzzle_to_continue),
            color = Color.White,
            style = font18.copy(fontWeight = FontWeight.Medium),
            modifier = Modifier.semantics { heading() },
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            stringResource(com.windscribe.vpn.R.string.slide_puzzle_piece_into_place),
            style = font12.copy(fontWeight = FontWeight.Normal),
            textAlign = TextAlign.Center,
            color = AppColors.white.copy(alpha = 0.50f),
            modifier = Modifier.width(150.dp),
        )
        if (error != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = error,
                style = font12,
                color = AppColors.red,
                textAlign = TextAlign.Center,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
        Box {
            Box(
                modifier =
                    Modifier
                        .border(
                            width = 1.dp,
                            color = AppColors.white.copy(alpha = 0.05f),
                            shape = shape,
                        ).clip(shape)
                        .background(Color.Transparent)
                        .padding(1.dp),
            ) {
                Image(
                    bitmap = backgroundBitmap,
                    contentDescription = puzzleDescription,
                    modifier =
                        with(density) {
                            Modifier
                                .height(backgroundSize.value.height.toDp())
                                .width(backgroundSize.value.width.toDp())
                        },
                    contentScale = ContentScale.FillBounds,
                )
            }

            // Draggable slider
            Box(
                modifier =
                    with(density) {
                        Modifier
                            .offset(x = sliderPositionX.floatValue.toDp(), y = sliderPositionY.floatValue.toDp())
                            .size(scaledSliderWidth.toDp(), scaledSliderHeight.toDp())
                            .semantics {
                                contentDescription = pieceDescription
                                stateDescription =
                                    "${((sliderPositionX.floatValue / maxX) * 100).toInt()}%"
                                // Lets switch access and keyboard users position the piece without a drag gesture.
                                customActions =
                                    listOf(
                                        CustomAccessibilityAction(moveRightLabel) { nudge(1) },
                                        CustomAccessibilityAction(moveLeftLabel) { nudge(-1) },
                                    )
                            }.pointerInput(Unit) {
                                detectDragGestures(
                                    onDrag = { change, dragAmount ->
                                        change.consume()
                                        val newX =
                                            (sliderPositionX.floatValue + dragAmount.x).coerceIn(
                                                0f,
                                                backgroundSize.value.width - scaledSliderWidth.toFloat(),
                                            )
                                        val newY =
                                            (sliderPositionY.floatValue + dragAmount.y).coerceIn(
                                                0f,
                                                backgroundSize.value.height - scaledSliderHeight.toFloat(),
                                            )
                                        recordPoint(newX, newY)
                                        dragJob.value?.cancel()
                                    },
                                    onDragEnd = { scheduleSubmit() },
                                    onDragStart = { dragJob.value?.cancel() },
                                )
                            }
                    },
            ) {
                Image(
                    bitmap = sliderBitmap,
                    contentDescription = null,
                    contentScale = ContentScale.FillBounds,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
        NextButtonLighterNoPadding(modifier = Modifier.width(235.dp), text = stringResource(id = com.windscribe.vpn.R.string.cancel)) {
            onCancel()
        }
    }
}
