# Private Android fork workflow

This repository is private and keeps the Windscribe upstream history. The local `upstream` remote points to `Windscribe/Android-App`; `origin` points to this private repository.

## Bring in upstream changes

In GitHub, open **Actions → Prepare upstream update pull request → Run workflow**. It fetches upstream `main`, applies changes since the recorded upstream base to a review branch, and opens a pull request. Review the diff, resolve any conflicts, merge, then build a new test APK.

## Build test APKs

Run **Actions → Build Android private test APKs → Run workflow**. It produces F-Droid debug APKs for ARM 32-bit, ARM 64-bit, and universal installation. Builds are manually triggered; they are not automatically published.

The workflow expects the repository Actions secret `ANDROID_TEST_KEYSTORE_B64`, containing the base64 encoding of the private employee debug keystore already used for local test builds. Keeping the same key lets Android install later APKs as updates. Do not add the keystore file or its contents to Git. Artifacts expire after 14 days.

