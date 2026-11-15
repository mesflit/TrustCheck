# Translations

| Locale | Folder | Status |
|---|---|---|
| English (default, fallback) | `values/` | complete |
| Türkçe | `values-tr/` | complete |
| Deutsch | `values-de/` | complete |
| Español | `values-es/` | complete |
| Français | `values-fr/` | complete |
| Português (Brasil) | `values-pt-rBR/` | complete |
| العربية (RTL) | `values-ar/` | complete |
| 日本語 | `values-ja/` | complete |
| Русский | `values-ru/` | complete |

`StringResourcesTest` fails the build if any locale is missing a key, has an extra key, has an
empty value, or uses different placeholders (`%1$s`, `%1$d`) than English.

## Improving a translation

Edit `app/src/main/res/values-<locale>/strings.xml`. Keep the `name` attribute and every
placeholder unchanged. Escape apostrophes and quotes (`\'`, `\"`) and `&` as `&amp;`. Keep brand
and product names (TrustCheck, Google Play, Google Safe Browsing) untranslated.

## Adding a string

1. Add it to `values/strings.xml` (English).
2. Add the same key to **every** locale file. If you cannot translate it, open the PR anyway and
   ask for help, but do not merge until all locales are filled in. Partial locales are not shipped.
3. Reference it with `stringResource(R.string.key)` in Compose or `getString()` elsewhere.
   Never hardcode user-facing text in Kotlin.

## Adding a language

1. Add an entry to `AppLanguage` (tag, native name, `isRtl`).
2. Create `res/values-<qualifier>/strings.xml` with all keys.
3. Add the folder to `localeFolders` in `StringResourcesTest`.
4. Add the language’s phrases to `ScamTextAnalyzer` (urgency, credentials, prizes, payments).
5. `generateLocaleConfig` picks the folder up automatically for Android’s per-app language settings.

Notifications and AI explanations follow the selected language (`LocaleController.localizedContext`
and the `language` field sent to the AI backend).
