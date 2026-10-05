package com.windscribe.tv.welcome.fragment

import android.app.Application
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import com.windscribe.tv.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(
    application = Application::class,
    sdk = [35],
)
class LoginFragmentTest {
    @Test
    fun `code display and expiry reset QR visibility and D-pad focus`() {
        val activity = Robolectric.buildActivity(TestActivity::class.java).setup().get()
        val fragment = LoginFragment()
        activity.supportFragmentManager
            .beginTransaction()
            .add(android.R.id.content, fragment)
            .commitNow()

        val root = fragment.requireView()
        val generateCode = root.findViewById<View>(R.id.generate_code)
        val manualContainer = root.findViewById<View>(R.id.manual_login_container)
        val qrContainer = root.findViewById<View>(R.id.qr_login_container)
        val qrFrame = root.findViewById<View>(R.id.qr_frame)
        val qrCode = root.findViewById<ImageView>(R.id.qr_code)
        val secretCode = root.findViewById<TextView>(R.id.secret_code)
        val usernameContainer = root.findViewById<View>(R.id.username_container)
        val minimumQrSize = (225 * root.resources.displayMetrics.density).toInt()

        assertTrue(qrFrame.layoutParams.width >= minimumQrSize)
        assertEquals(qrFrame.layoutParams.width, qrFrame.layoutParams.height)

        generateCode.requestFocus()
        fragment.setSecretCode("AB12-CD34")

        assertEquals(View.GONE, manualContainer.visibility)
        assertEquals(View.VISIBLE, qrContainer.visibility)
        assertEquals("AB12-CD34", secretCode.text.toString())
        assertTrue(usernameContainer.hasFocus())

        qrCode.setImageResource(android.R.drawable.ic_menu_camera)
        fragment.setSecretCode("")

        assertEquals(View.VISIBLE, manualContainer.visibility)
        assertEquals(View.GONE, qrContainer.visibility)
        assertEquals("", secretCode.text.toString())
        assertNull(qrCode.drawable)
        assertTrue(generateCode.hasFocus())
    }

    class TestActivity : FragmentActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
            setTheme(R.style.AppTheme_NoActionBar)
            super.onCreate(savedInstanceState)
        }
    }
}
