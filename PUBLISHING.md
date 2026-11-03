# Publishing Nova — checklist

## 1. Decide the license (do this first)
Nova uses **PyQt6, which is GPLv3 or commercial**. If you distribute Nova you must either:
- release Nova's source under GPLv3 (simplest, free), **or**
- buy a PyQt commercial license from Riverbank, **or**
- port to **PySide6** (LGPL) — only a few imports change.
Also ship the license texts for Qt/Chromium, Tor (BSD) and your own code. Put your license in `LICENSE.txt`
and uncomment `LicenseFile=` in `installer.iss`.

## 2. Name and branding
Search for "Nova" trademarks in software before launching; rename by editing the strings in
`nova_browser.py`, `installer.iss`, the website and `nova.ico`. Never call it "Tor Browser".

## 3. Set your update channel (once)
```
pip install cryptography
python sign_update.py keygen          # keep update_private.key secret + backed up
```
In `nova_browser.py` set `DEFAULT_UPDATE_URL` (e.g. https://yourdomain.com/update.json) and
`DEFAULT_UPDATE_PUBKEY` (printed by keygen) so every user gets signed updates with zero setup.

## 4. Build a release
1. Edit the `#define` lines at the top of `installer.iss`; bump `VERSION` in `nova_browser.py` and `MyAppVersion`.
2. Install Inno Setup (`winget install JRSoftware.InnoSetup`), run `build.bat` → `Output\NovaSetup.exe`.
3. Test on a clean Windows 10/11 machine or VM: install, browse, Tor window, download scan, Panic Wipe, uninstall.
4. `python sign_update.py sign --version 1.5.0 --url https://yourdomain.com/downloads/NovaSetup.exe`
   → upload `NovaSetup.exe` and `update.json`.

## 5. Publish the website
`website/index.html` is a single file. Edit the CONFIG block at the bottom (download URL, SHA-256 from
`Get-FileHash Output\NovaSetup.exe`, size, contact, source link) and host it on GitHub Pages, Netlify or
Cloudflare Pages. Large installers fit best on GitHub Releases — point `downloadUrl` at the release asset.

## 6. Trust and SmartScreen
Unsigned installers trigger Windows SmartScreen and some antivirus false positives (PyInstaller apps are often
flagged). A code-signing certificate (OV/EV, or Azure Trusted Signing) fixes this; until then the site tells users
how to proceed and shows the checksum. Submit each release to Microsoft Defender's false-positive portal.

## 7. Known limits to state publicly
No Chrome extensions, Windows only, no guaranteed DRM video, some H.264 video may not play (Qt WebEngine builds
omit proprietary codecs), Tor window ≠ Tor Browser. The site already says so — keep it that way.
