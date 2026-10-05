package com.windscribe.tv.welcome.fragment

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.windscribe.vpn.constants.NetworkKeyConstants
import java.net.URLEncoder

internal object LazyLoginQrCode {
    private const val QUIET_ZONE_MODULES = 4

    fun loginUrl(code: String): String =
        loginUrl(
            NetworkKeyConstants.getWebsiteLink(""),
            code,
        )

    internal fun loginUrl(
        websiteBaseUrl: String,
        code: String,
    ): String {
        require(websiteBaseUrl.startsWith("https://"))
        val encodedCode = URLEncoder.encode(code, Charsets.UTF_8.name())
        return "${websiteBaseUrl.trimEnd('/')}/lazy?code=$encodedCode"
    }

    fun bitmap(
        value: String,
        width: Int,
        height: Int,
    ): Bitmap {
        val matrix = matrix(value, width, height)
        val pixels = pixels(matrix)
        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888)
    }

    internal fun matrix(
        value: String,
        width: Int,
        height: Int,
    ): BitMatrix =
        QRCodeWriter().encode(
            value,
            BarcodeFormat.QR_CODE,
            width,
            height,
            mapOf(
                EncodeHintType.CHARACTER_SET to Charsets.UTF_8.name(),
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
                EncodeHintType.MARGIN to QUIET_ZONE_MODULES,
            ),
        )

    internal fun pixels(matrix: BitMatrix): IntArray =
        IntArray(matrix.width * matrix.height) { index ->
            val x = index % matrix.width
            val y = index / matrix.width
            if (matrix.get(x, y)) Color.BLACK else Color.WHITE
        }
}
