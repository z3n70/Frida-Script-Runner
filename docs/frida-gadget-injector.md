# Frida Gadget Injector (Android)

The Frida Gadget Injector page (`/frida-gadget-injector`) patches an APK to embed Frida Gadget for a chosen architecture and version, optionally bundles a Frida script that autoloads at runtime, and rebuilds/signs the APK for installation.

- URL: `http://127.0.0.1:5000/frida-gadget-injector`
- Backend: Flask + Flask‑SocketIO in `frida_script.py`
- Frontend: `templates/frida_gadget_injector.html` + `static/js/frida_gadget_injector.js`

## What It Does

- Decodes the uploaded APK with `apktool`.
- Adds Frida Gadget library to `lib/<ABI>/lib<name>.so` (e.g., `lib/arm64-v8a/libfrida-gadget.so`).
- Creates a Frida Gadget config `lib/<ABI>/lib<name>.config.so` that either:
  - runs an embedded script at startup, or
  - listens on `127.0.0.1:27042` for remote attachment.
- If “Autoload” is enabled, injects a load hook so the gadget loads on app startup (Android manifest/smali changes with fallbacks).
- Rebuilds the APK with `apktool`, aligns and signs with Android build‑tools if available, and returns the final APK for download. One‑click install via ADB is available from the UI.

## Requirements

- Java/`apktool`
  - System `apktool` in `PATH`, or a bundled one under `tools/resources` or `resources` is auto‑detected.
- Android SDK build‑tools (optional but recommended)
  - `zipalign` and `apksigner` for align/sign. If missing, you still get an unsigned APK.
  - Windows default search: `%LOCALAPPDATA%\Android\Sdk\build-tools`.
- Network access (for release discovery and gadget download)
  - GitHub API is used to list releases and fetch `frida-gadget-*-android-*.so.xz`. Local cache is used when available.
- ADB (optional) for “Install to device” button.

## User Flow (UI)

1. Open `http://127.0.0.1:5000/frida-gadget-injector`.
2. Select an APK and target `Architecture` (ABI).
3. Choose `Frida Version` (Latest or a tag); uses local cache and GitHub.
4. Optional: change `Library Name` (default `frida-gadget`) to obfuscate.
5. Optional script to embed:
   - Pick from repo (`scripts/`), or
   - Upload `.js`, or
   - Paste inline script.
6. Check “Autoload Gadget at Startup” to hook early load via manifest/smali.
7. Click “Inject Gadget”. Watch live logs in “FSR Logs”.
8. Download the resulting APK or click “Install to device”.

## How It Works (Backend)

Endpoint: `POST /api/gadget/inject` in `frida_script.py`.

High‑level steps:

1. Save upload and pick tools
   - Resolves `apktool` from `PATH` or bundled resources.
   - Prepares a temporary working directory.
2. Decode APK
   - `apktool d` (full decode). Rejects split APKs (no base or launcher) for reliability.
3. Choose and place the gadget
   - Version specified → uses cache or downloads from GitHub, then decompresses `.xz`.
   - Places `lib<name>.so` into `lib/<ABI>/`.
4. Script and config
   - If a script is provided, it is wrapped for safer execution and saved as `libfsr-gadget-script.js.so`.
   - Writes `lib<name>.config.so` with either:
     - `{"interaction": {"type": "script", "path": "libfsr-gadget-script.js.so"}}`, or
     - `{"interaction": {"type": "listen", "address": "127.0.0.1", "port": 27042}}`.
5. Autoload strategies (if enabled)
   - Prefer minimal, stable changes; try in order:
     - No existing `android:name` → add `com.fsr.FSRApp` (Application with `System.loadLibrary(<name>)`).
     - Existing Application (non‑final) → generate `com.fsr.AppWrapper` that extends it and loads the library; set in manifest.
     - Fallback 1 → wrap `appComponentFactory` via `com.fsr.AppCF` overriding `instantiateApplication` to load library; set in manifest.
     - Fallback 2 → inject a `ContentProvider` (`com.fsr.FSRInit`) with high `initOrder` to load early.
     - Fallback 3 → inject `System.loadLibrary` into main Activity’s `onCreate` in smali.
6. Build + sign
   - Sanitizes resource names for `aapt` compliance.
   - `apktool b` to produce an unsigned APK.
   - If build‑tools found, runs `zipalign` and `apksigner` (creates a debug keystore if needed) and returns the signed APK.
7. Response
   - Returns the final APK binary. Frontend shows a download link and an “Install to device” button that calls `POST /install-apk` (runs `adb install -r`).

## Repackaging Pipeline

- Decode APK
  - Uses `apktool d` via `_run_apktool_decode_full` to a temp workdir (`/api/gadget/inject`). See `frida_script.py:1814`.
  - Rejects split APKs (no base Application/Launcher). See `frida_script.py:1823`.
- Place Gadget + Config
  - Writes `lib/<ABI>/lib<name>.so` and `lib/<ABI>/lib<name>.config.so`. See placement around `frida_script.py:1836`–`frida_script.py:1961`.
- Optional Script
  - If provided, wraps and writes to `lib/<ABI>/libfsr-gadget-script.js.so` and points config to it. See `frida_script.py:1857`–`frida_script.py:1915`.
- Autoload Injection (optional)
  - Modifies manifest/smali to load `System.loadLibrary(<name>)` at startup (details below).
- Sanitize + Build
  - Resource name sanitize for aapt compliance: `frida_script.py:2076`.
  - Build with `apktool b`: `frida_script.py:2080`.
- Align + Sign (if tools available)
  - `zipalign` and `apksigner` via `_fallback_align_and_sign` (debug keystore auto‑generated if needed). See `frida_script.py:2201` (definition) and call around `frida_script.py:2102`.
- Return
  - Sends signed (or unsigned fallback) APK to the client. See `frida_script.py:2110`.

## Added/Modified In APK

- Libraries (under `lib/<ABI>/`)
  - `lib<name>.so`: The Frida Gadget binary for the selected ABI (e.g., `libfrida-gadget.so` or a custom name).
  - `lib<name>.config.so`: JSON config controlling gadget behavior (script or listen mode).
  - `libfsr-gadget-script.js.so`: Only when you embed a script; contains the wrapped JavaScript.

- Gadget Config (`lib<name>.config.so`)
  - Script mode example:
    - `{ "interaction": { "type": "script", "path": "libfsr-gadget-script.js.so" } }`
  - Listen mode example:
    - `{ "interaction": { "type": "listen", "address": "127.0.0.1", "port": 27042 } }`

- Manifest/Smali (only if Autoload is checked)
  - New Application when none present
    - Sets `android:name="com.fsr.FSRApp"` and adds `com/fsr/FSRApp.smali`:
      - Calls `System.loadLibrary("<name>")` in `onCreate()`. See `frida_script.py:711` and `frida_script.py:760`.
  - Application wrapper when one exists (and not `final`)
    - Adds `com/fsr/AppWrapper.smali` extending the original Application and updates manifest `android:name` to wrapper. See `frida_script.py:771` and manifest setters around `frida_script.py:826`.
  - AppComponentFactory wrapper
    - Adds `com/fsr/AppCF.smali` to hook `instantiateApplication` and inject `System.loadLibrary`. See `frida_script.py:871` and setters around `frida_script.py:926`.
  - ContentProvider autoload (early init)
    - Adds `com/fsr/FSRInit.smali` and inserts a `<provider>` with `android:initOrder="199999"`, `exported="false"`, `authorities="<package>.fsrinit"`. See `frida_script.py:1219`, `frida_script.py:1338`–`frida_script.py:1463`.
  - Activity fallback
    - Injects `System.loadLibrary` into main Activity `onCreate` smali. See `frida_script.py:1496`–`frida_script.py:1554`.

- Resource Sanitize (build reliability)
  - Invalid resource basenames are normalized and references updated for aapt/aapt2. See `frida_script.py:995`–`frida_script.py:1086`.

Notes:
- If Autoload is unchecked, only `lib/<ABI>/lib<name>.so` and `lib/<ABI>/lib<name>.config.so` (and optional script) are added; the manifest is not changed.
- Custom `Library Name` alters both the gadget and config filenames to match (`lib<name>.so` / `lib<name>.config.so`).

## Related Files & Endpoints

- UI: `templates/frida_gadget_injector.html`, `static/js/frida_gadget_injector.js`
- Gadget injector API:
  - `GET /frida-gadget-injector` → page
  - `POST /api/gadget/inject` → returns injected APK
  - `POST /install-apk` → ADB install (optional)
  - `GET /api/scripts/list` → lists `scripts/` repo scripts
  - `GET /api/frida/releases` → Frida tags from GitHub
  - `GET /api/gadget/local` → lists cached gadgets
- Gadget cache manager (optional helper UI): `GET /frida-gadget-manager`
  - `POST /api/gadget/download` → download + cache gadget
  - `POST /api/gadget/delete` → delete cached version/ABI
  - `POST /api/gadget/rename` → copy/rename cached gadget to custom `lib<name>.so`

## Cache Layout

Gadgets are cached under:

```
frida-gadget/android/<version>/<abi>/libfrida-gadget.so
```

You may use the Gadget Manager UI to copy/rename cached gadget libraries (e.g., `libmyg.so`). The injector accepts a custom `Library Name` and will produce `lib<name>.so` and `lib<name>.config.so` in the target APK.

## Notes on Embedded Script

- When you provide a script, it is wrapped in a safe closure that tries `Java.perform(...)` when possible and logs via `android.util.Log`.
- The script is stored beside the gadget as `libfsr-gadget-script.js.so`, and the gadget config references that path.
- If no script is provided, the config is set to `listen` mode on `127.0.0.1:27042` so you can attach with Frida tools.

## Troubleshooting

- “Apktool not found”
  - Install `apktool` (system) or place a valid `apktool`, `apktool.exe`, or highest‑version `apktool_*.jar` in `tools/resources` or `resources`.
- “zipalign/apksigner not found”
  - Install Android SDK build‑tools or ensure `zipalign` and `apksigner` are in `PATH`. Without them, the returned APK is unsigned.
- “Split APK not supported”
  - Use a base/universal APK (APK with launcher activity and application), not a split or config APK.
- App fails to autoload gadget
  - Uncheck “Autoload” and use `listen` mode, then attach with Frida.
  - Try another ABI or Frida version that matches device/server.
- Install fails
  - Ensure `adb devices` shows your device and USB debugging authorization is granted.

## Quick Start (Run Locally)

- Start the server (default port 5000):

```
python frida_script.py -p 5000
```

- Visit `http://127.0.0.1:5000/frida-gadget-injector` and follow the UI steps.

## Security & Legal

Use only on APKs and devices you own or are authorized to test. Embedding Frida Gadget changes application behavior and may trigger tamper protections; for red‑team/pentest and research under appropriate legal scope.
