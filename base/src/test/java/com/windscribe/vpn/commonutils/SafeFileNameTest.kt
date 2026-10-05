package com.windscribe.vpn.commonutils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SafeFileNameTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `sanitize keeps an ordinary file name`() {
        assertEquals("beep.mp3", SafeFileName.sanitize("beep.mp3"))
        assertEquals("my sound (1).ogg", SafeFileName.sanitize("my sound (1).ogg"))
    }

    @Test
    fun `sanitize strips traversal segments to the bare name`() {
        // The payloads from the report: a display name aimed at the serialized VPN profile and at
        // the app's preferences must not keep any directory part.
        assertEquals("wd.vp", SafeFileName.sanitize("../files/wd.vp"))
        assertEquals("wd.vp", SafeFileName.sanitize("../../files/wd.vp"))
        assertEquals(
            "com.windscribe.vpn_preferences.xml",
            SafeFileName.sanitize("../shared_prefs/com.windscribe.vpn_preferences.xml"),
        )
        assertEquals("config.toml", SafeFileName.sanitize("/data/user/0/pkg/files/config.toml"))
    }

    @Test
    fun `sanitize rejects names that are not usable components`() {
        assertNull(SafeFileName.sanitize(""))
        assertNull(SafeFileName.sanitize("."))
        assertNull(SafeFileName.sanitize(".."))
        assertNull(SafeFileName.sanitize("/"))
        assertNull(SafeFileName.sanitize("../"))
    }

    @Test
    fun `sanitize drops a trailing separator rather than rejecting the name`() {
        // File.name normalizes the trailing slash away, leaving a usable single component.
        assertEquals("foo", SafeFileName.sanitize("foo/"))
        assertEquals("beep.mp3", SafeFileName.sanitize("sounds/beep.mp3/"))
    }

    @Test
    fun `sanitize rejects backslash separators the platform does not split on`() {
        // File.name only splits on '/', so a backslash would otherwise survive into the path.
        assertNull(SafeFileName.sanitize("..\\files\\wd.vp"))
        assertNull(SafeFileName.sanitize("a\\b"))
    }

    @Test
    fun `isInside accepts a file directly in the directory`() {
        val dir = temporaryFolder.newFolder("sounds")

        assertTrue(SafeFileName.isInside(File(dir, "beep.mp3"), dir))
    }

    @Test
    fun `isInside rejects a traversal out of the directory`() {
        val dir = temporaryFolder.newFolder("sounds")

        assertFalse(SafeFileName.isInside(File(dir, "../wd.vp"), dir))
        assertFalse(SafeFileName.isInside(File(dir.parentFile, "wd.vp"), dir))
    }

    @Test
    fun `isInside rejects the directory itself`() {
        val dir = temporaryFolder.newFolder("sounds")

        assertFalse(SafeFileName.isInside(dir, dir))
    }
}
