package com.windscribe.vpn.commonutils

import java.io.File

object SafeFileName {
    /**
     * Reduces [name] to a bare file name usable as a single path component, or returns null if it
     * cannot be one.
     *
     * Intended for names that arrive from outside the app — most importantly a DocumentsProvider's
     * COLUMN_DISPLAY_NAME, which any installed app can choose freely. `File(parent, child)`
     * concatenates rather than resolves, so an unchecked name containing `../` escapes the
     * directory it was meant to land in and lets the caller write over unrelated app-private
     * files. Callers must still confirm the resolved file sits inside the intended directory; see
     * [isInside].
     */
    fun sanitize(name: String): String? {
        // File(..).name keeps only the segment after the last separator, so any directory part -
        // including "../" - is dropped rather than honoured.
        val bare = File(name).name
        return when {
            bare.isEmpty() -> null
            bare == "." || bare == ".." -> null
            // Guards against separators the platform does not treat as such (File.name only splits
            // on '/'), which would otherwise survive into a path built from this value.
            bare.contains('/') || bare.contains('\\') -> null
            else -> bare
        }
    }

    /**
     * True if [file] resolves to a location inside [directory]. Uses canonical paths so symlinks
     * and unresolved `..` segments cannot point outside. Returns false if either path cannot be
     * canonicalized.
     */
    fun isInside(
        file: File,
        directory: File,
    ): Boolean =
        runCatching {
            file.canonicalPath.startsWith(directory.canonicalPath + File.separator)
        }.getOrDefault(false)
}
