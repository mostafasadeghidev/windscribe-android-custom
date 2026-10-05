package com.windscribe.tv.welcome.fragment

import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.junit.Assert.assertEquals
import org.junit.Test

class LazyLoginQrCodeTest {
    @Test
    fun `login URL uses production website and formatted code`() {
        assertEquals(
            "https://www.windscribe.com/lazy?code=AB12-CD34",
            LazyLoginQrCode.loginUrl("https://www.windscribe.com", "AB12-CD34"),
        )
    }

    @Test
    fun `login URL uses staging website without adding a double slash`() {
        assertEquals(
            "https://www-staging.windscribe.com/lazy?code=AB12-CD34",
            LazyLoginQrCode.loginUrl("https://www-staging.windscribe.com/", "AB12-CD34"),
        )
    }

    @Test
    fun `generated QR code decodes to login URL`() {
        val url = "https://www.windscribe.com/lazy?code=AB12-CD34"
        val matrix = LazyLoginQrCode.matrix(url, 384, 384)
        val bitmap =
            BinaryBitmap(
                HybridBinarizer(
                    RGBLuminanceSource(matrix.width, matrix.height, LazyLoginQrCode.pixels(matrix)),
                ),
            )

        assertEquals(url, QRCodeReader().decode(bitmap).text)
    }
}
