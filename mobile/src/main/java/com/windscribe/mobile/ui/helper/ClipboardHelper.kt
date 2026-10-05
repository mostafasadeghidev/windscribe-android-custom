package com.windscribe.mobile.ui.helper

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle

/**
 * Copies [text] to the system clipboard under [label].
 *
 * When [sensitive] is true the clip is flagged with [ClipDescription.EXTRA_IS_SENSITIVE], which
 * tells the OS to omit the value from the clipboard preview overlay and from clipboard-history
 * surfaces. Pass true for anything that authenticates the account — passwords and account hashes
 * (a hashed account's hash is both its username and its password).
 *
 * The flag only exists from API 33; below that the platform has no notion of clip sensitivity and
 * the clip is copied unflagged.
 */
fun copyTextToClipboard(
    context: Context,
    label: String,
    text: String,
    sensitive: Boolean,
) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, text)
    if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras =
            PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
    }
    clipboard.setPrimaryClip(clip)
}
