# Nova Browser 1.5

Chromium (QtWebEngine) browser. Build: double-click `build.bat`.
To run from source use matching Qt versions (mixing them causes the QtWebEngineCore DLL error):
`pip install "PyQt6>=6.7,<6.8" "PyQt6-Qt6>=6.7,<6.8" "PyQt6-WebEngine>=6.7,<6.8" "PyQt6-WebEngine-Qt6>=6.7,<6.8" psutil cryptography`

## New in 1.5
Bookmarks bar + Library (bookmarks, history, pinboards, Flow, downloads, site permissions) · address-bar suggestions ·
tab search (Ctrl+Shift+A) · command palette (Ctrl+Shift+P) · colour-coded tab islands · Easy Files picker · autofill
(addresses & cards, encrypted) · translate page · cookie-banner auto-reject · optional Google Safe Browsing ·
content-script extensions · more sidebar apps + custom apps · media controls · multiple profiles (`--profile NAME`) ·
Razer Chroma · letterboxing and Tor Safer level · security checkup · Panic Wipe "scorched earth" + free-space overwrite ·
hardening pass (see SECURITY.md) · experimental macOS/Linux build scripts.

## Files
`nova_browser.py` app · `build.bat` one-click build · `installer.iss` Windows installer · `sign_update.py` signed updates ·
`website/index.html` 3D download site · `PUBLISHING.md` release checklist · `SECURITY.md` hardening notes · `build_linux.sh` / `build_macos.sh` experimental.

## Honest limits
No browser makes you untraceable. Nova reduces tracking and fingerprinting and can route through Tor,
but your accounts, behaviour, writing style, and your ISP/network still identify you. For serious
anonymity use Tor Browser or Tails. Nova's Tor window has no letterboxing and a smaller anonymity set.

## Privacy & security
- Shields: ads/trackers, per-site on/off, EasyList/EasyPrivacy, malware host lists (URLhaus), cosmetic filtering
- HTTPS-only upgrade, 3rd-party cookie blocking, tracking-parameter stripping, GPC/DNT
- Fingerprinting: canvas/audio noise, fixed hardware values, spoofed screen, UA-data and WebGL strings,
  optional UTC timezone and WebRTC-off; "QtWebEngine" removed from the User-Agent; fixed Accept-Language
- Chromium telemetry/background networking, Privacy Sandbox, prefetch, link-ping disabled
- NoScript-style per-site JavaScript toggle; popup blocker; risky-download warnings; permission prompts
- Paranoid mode (nothing written to disk), clear-on-exit, Panic wipe & exit (Ctrl+Shift+Backspace)
- Master password (scrypt + AES-256-GCM) encrypting bookmarks/history/session/workspaces/vault
- Vault password manager with phishing-safe autofill and generator; encrypted backup/sync file
- DoH (best-effort), custom proxy, Tor windows (bridges, per-destination circuits, Safest level, New identity)
- Signed auto-updates (Ed25519) - see sign_update.py

## GX-style
RAM/CPU/tab limiters, Hot Tabs Killer, network limiter (experimental), Cleaner, side-panel messengers/split view,
music player, themes, image/.webm live wallpaper, sounds, CSS mods, GX Corner deals, workspaces, pinned/muted tabs,
floating (picture-in-picture) video window.

## Also
Reader mode, userscripts, Ask Claude sidebar (opt-in, your key), IPFS links, find, zoom, PDF, screenshots, dev tools.

## Panic Wipe (Ctrl+Shift+Backspace, or the red 🚨 button)
Hides every window, kills all Nova processes (including Tor), then a detached helper waits for them to exit and
securely overwrites + deletes: cookies, cache, site data, history, session, workspaces, Tor state, and optionally
Nova-downloaded files, screenshots and bookmarks. It also flushes the Windows DNS cache.
It cannot erase what websites, your ISP/employer network, the OS (pagefile, Recent items, prefetch) or SSD
wear-levelling keep.

## VPN (bring your own provider)
Nova ships no VPN servers. It has two clients: a proxy VPN for Nova's traffic (HTTPS/SOCKS5 proxy from your
provider, fail-closed, DNS through the proxy) and a WireGuard manager for the whole PC (needs WireGuard for
Windows; kill switch via AllowedIPs = 0.0.0.0/0).

## Antivirus
No home-made engine. Every download gets the Windows Mark-of-the-Web, a Microsoft Defender scan (MpCmdRun),
disguised-executable checks, optional VirusTotal hash lookup (your key; only the hash is sent) and quarantine.
Phishing (OpenPhish) and malware (URLhaus) lists block known bad pages.

## Not possible
Chrome extensions, Brave Wallet/Rewards/Sync servers/VPN, Twitch/Razer Chroma integrations, mods store,
Netflix-class DRM unless Widevine is found from an installed Chrome/Edge (best-effort).
