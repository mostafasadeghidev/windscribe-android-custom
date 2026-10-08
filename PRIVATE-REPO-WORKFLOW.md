# Private Android fork workflow

This repository is private and keeps the Windscribe upstream history. The local `upstream` remote points to `Windscribe/Android-App`; `origin` points to this private repository.

## Bring in upstream changes

In GitHub, open **Actions → Prepare upstream update pull request → Run workflow**. It fetches upstream `main`, applies changes since the recorded upstream base to a review branch, and opens a pull request. Review the diff, resolve any conflicts, merge, then build a new test APK.

## Build test APKs

Run **Actions → Build Android private test APKs → Run workflow**. It produces F-Droid debug APKs for ARM 32-bit, ARM 64-bit, and universal installation. Builds are manually triggered; they are not automatically published.

The workflow reads the repository Actions secret `ANDROID_TEST_KEYSTORE_B64`, containing the base64 encoding of the existing private test keystore. It is stored in GitHub Actions secrets and is not committed to Git. Keeping this keystore lets Android install later APKs as updates to builds signed with the same key. Artifacts expire after 14 days.

Each successful build also attaches the three APKs to a GitHub pre-release tagged `v<appVersionName>-private-<short commit>`. Releases do not expire; use the **Releases** page for downloads that must outlive the 14-day artifact window.

## Install updates

Private test builds skip Windscribe's update-check API. Download replacement APKs from this repository's **Releases** page (or the **Actions** artifacts) and install them manually. A private GitHub repository cannot provide an in-app updater to an installed client without a separate authenticated update service; never embed a GitHub token in the app.

