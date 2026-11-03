# Nova security notes

No software is "unhackable", and nobody can promise that every loophole is closed. This file states what Nova
does, what it doesn't, and how to keep it safe once published.

## Hardening built in
- **Engine:** Chromium sandbox forced on (sandbox-disabling and remote-debugging environment variables are removed at
  start); site isolation left at Chromium defaults; telemetry, background networking, Privacy Sandbox, prefetch and
  link-ping switched off.
- **Navigation:** only safe link types are opened (ms-msdt:, search-ms:, vbscript: etc. are blocked); web pages can't
  open `file://` links; `javascript:` and script-data URLs pasted in the address bar are refused; popups need a user action.
- **TLS:** certificate errors are never click-through (only localhost development servers are allowed).
- **Downloads:** Mark-of-the-Web, Microsoft Defender scan, disguised-executable checks, risky-file warnings, quarantine.
- **Updates:** HTTPS-only, no downgrade redirects, Ed25519-signed manifest, SHA-256 checked twice (before and right
  before running), size-capped downloads.
- **Local data:** master password (scrypt + AES-256-GCM) encrypts bookmarks, history, session, pinboards, Flow and the
  vault; vault autofill works only on HTTPS and only on the matching site; clipboard is cleared after 20 s.
- **Injection guards:** filter lists can't smuggle CSS (`{ } ; url() @import` rejected); extension files can't escape
  their folder; extension scripts run in an isolated world; the Windows DLL search path excludes the current folder.
- **Panic Wipe:** see README. It cannot erase what websites, networks or the OS keep.

## Known limits (be honest with users)
- Nova's engine is Chromium **as packaged by Qt WebEngine**; fixes arrive when you rebuild with a newer Qt. Rebuild and
  ship at least monthly, and subscribe to Qt and Chromium security advisories. The in-app Security checkup shows the
  engine version.
- Extensions are limited to content scripts: an installed extension can read and change the pages it matches. Install
  only what you trust. The optional local bandwidth-limiter proxy listens on 127.0.0.1 and is off by default.
- Unsigned Windows installers trigger SmartScreen. Sign your releases.
- Optional features send data to third parties **only when you turn them on** (Safe Browsing, VirusTotal, translation, AI).

## Before every release
1. Rebuild in a clean environment with pinned, current Qt 6.7.x (or newer tested) packages.
2. Run `pip list` and check PyQt6, PyQt6-Qt6, PyQt6-WebEngine-Qt6, cryptography, psutil for advisories.
3. Test on a clean Windows 10/11 VM: install, upgrade over the previous version, uninstall, Panic Wipe, Tor window.
4. Sign the installer; sign `update.json` with `sign_update.py`; keep the private key offline.
5. Publish the SHA-256 on the website.

## Reporting vulnerabilities
Replace this section with your contact (for example security@yourdomain.com), a PGP key if you use one, and a promise
to acknowledge reports within a few days. Consider adding `/.well-known/security.txt` to your website.
