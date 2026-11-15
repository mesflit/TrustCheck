# Releasing

## One-time setup

### 1. Create an upload/signing keystore (locally, never commit it)

```bash
keytool -genkeypair -v -keystore trustcheck-release.jks -alias trustcheck \
  -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 trustcheck-release.jks > keystore.b64      # macOS: base64 -i trustcheck-release.jks
```

Store the `.jks` and passwords in a password manager. Losing them means you cannot update the app.
For Google Play, enrol in **Play App Signing** and use this key as the *upload* key.

### 2. Add GitHub Actions secrets

Repository → Settings → Secrets and variables → Actions → **New repository secret**:

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | contents of `keystore.b64` |
| `ANDROID_KEYSTORE_PASSWORD` | keystore password |
| `ANDROID_KEY_ALIAS` | `trustcheck` (or your alias) |
| `ANDROID_KEY_PASSWORD` | key password |
| `ADMOB_APP_ID` *(optional)* | production AdMob app ID |
| `ADMOB_BANNER_ID` *(optional)* | production banner unit ID |
| `ADMOB_REWARDED_ID` *(optional)* | production rewarded unit ID |

Optional **repository variable** (not secret): `TRUSTCHECK_BACKEND_URL` = `https://…/`.

Delete `keystore.b64` afterwards. Restricting releases to protected tags
(Settings → Rules → Tag rulesets for `v*`) is recommended.

## Publishing a release

```bash
git switch main && git pull
git tag v0.1.0
git push origin v0.1.0
```

Or run **Actions → Android Release → Run workflow** and enter `0.1.0`. The current commit is tagged.

The workflow then:

1. checks out the exact tag, validates the version and refuses to overwrite an existing release,
2. **fails with the list of missing secrets** if signing is not configured, so no unsigned binary is published,
3. runs the unit tests,
4. builds the signed `app-release.apk` and `app-release.aab` (versionName = tag, versionCode = MAJOR·10⁶ + MINOR·10³ + PATCH),
5. verifies the signatures (`apksigner`, `jarsigner`),
6. writes `SHA256SUMS.txt` and per-file `.sha256`,
7. generates release notes from commits since the previous tag,
8. creates a **published** GitHub Release (pre-release for `-beta`/`-rc` tags), attaches the APK,
   AAB and checksums, and confirms that the release is not a draft and that the assets are attached.

## Uploading to Google Play

Download `TrustCheck-vX.Y.Z.aab` from the release and upload it in Play Console (or add a
Play-publishing step later with a service-account secret; nothing is published to Play automatically).

## Before the first production release

- [ ] Play Console: create subscription `trustcheck_premium` with base plans `monthly` and `annual`
- [ ] Play Console: Data safety form (see PRIVACY_POLICY.md), ads declaration, Notification
      Listener / sensitive-permission declaration with a demo video
- [ ] AdMob: production IDs as secrets, UMP consent message published in AdMob → Privacy & messaging
- [ ] Backend deployed and `TRUSTCHECK_BACKEND_URL` set (otherwise cloud features stay off)
- [ ] Privacy policy hosted at a public URL
