"""
Nova Browser 1.1 - Chromium (QtWebEngine) browser with Brave-style privacy
and Opera GX-style performance/personalisation features, plus Tor windows,
userscripts, filter lists and auto-update.

Install:  pip install PyQt6 PyQt6-WebEngine psutil
Run:      python nova_browser.py          (Tor window: python nova_browser.py --tor)
Build:    double-click build.bat
"""
import sys, os, re, json, time, math, wave, struct, socket, hashlib, shutil
import subprocess, tempfile, string, secrets, threading, asyncio, base64, ctypes, zipfile, io
import urllib.request, urllib.error, urllib.parse, html as htmllib
from pathlib import Path
from urllib.parse import quote

# ---- process hardening (runs before Qt loads) ----
if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.SetDllDirectoryW("")      # never load DLLs from the current directory (DLL planting)
    except Exception:
        pass
for _k in ("QTWEBENGINE_DISABLE_SANDBOX", "QTWEBENGINE_REMOTE_DEBUGGING"):
    os.environ.pop(_k, None)                              # keep the Chromium sandbox on; no remote debugging port
if "--no-sandbox" in os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", ""):
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = os.environ["QTWEBENGINE_CHROMIUM_FLAGS"].replace("--no-sandbox", "")

import psutil
from PyQt6.QtCore import (QUrl, QUrlQuery, Qt, QTimer, QProcess, QThread, QStandardPaths, QSize,
                          QByteArray, QRectF, QStringListModel, QEvent, QT_VERSION_STR, pyqtSignal)
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QColor, QPixmap, QPainter, QPalette, QDesktopServices
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QTabBar, QToolBar, QLineEdit, QLabel,
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QSpinBox,
    QPushButton, QMenu, QMessageBox, QFileDialog, QInputDialog, QComboBox,
    QScrollArea, QGroupBox, QListWidget, QListWidgetItem, QSlider, QToolButton,
    QSizePolicy, QDialog, QPlainTextEdit, QTextBrowser, QStackedWidget, QCompleter,
)
try:
    from PyQt6.QtWebEngineCore import (
        QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineScript,
        QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo, QWebEngineDownloadRequest,
    )
    from PyQt6.QtWebEngineWidgets import QWebEngineView
except ImportError as _err:
    _msg = ("Qt WebEngine could not be loaded:\n%s\n\n"
            "This is almost always (1) mismatched PyQt6 package versions or (2) the Microsoft Visual C++ "
            "2015-2022 x64 runtime missing.\n\n"
            "Fix: re-run build.bat (it now installs matching versions in a clean environment), or run in PowerShell:\n"
            "pip uninstall -y PyQt6 PyQt6-Qt6 PyQt6-sip PyQt6-WebEngine PyQt6-WebEngine-Qt6\n"
            "pip install \"PyQt6>=6.7,<6.8\" \"PyQt6-Qt6>=6.7,<6.8\" \"PyQt6-WebEngine>=6.7,<6.8\" \"PyQt6-WebEngine-Qt6>=6.7,<6.8\"\n\n"
            "VC++ runtime: https://aka.ms/vs/17/release/vc_redist.x64.exe") % _err
    if sys.platform == "win32":
        ctypes.windll.user32.MessageBoxW(0, _msg, "Nova - Qt WebEngine failed to load", 0x10)
    else:
        print(_msg)
    sys.exit(1)

try:
    from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput, QSoundEffect
    HAVE_AUDIO = True
except Exception:
    HAVE_AUDIO = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

try:
    from PyQt6.QtSvg import QSvgRenderer
    HAVE_SVG = True
except Exception:
    HAVE_SVG = False
from PyQt6.QtNetwork import QLocalServer, QLocalSocket

VERSION = "1.5.0"
# PUBLISHERS: set these before building so every user gets signed auto-updates with zero setup
DEFAULT_UPDATE_URL = ""       # e.g. "https://yourdomain.com/update.json"
DEFAULT_UPDATE_PUBKEY = ""    # public key printed by:  python sign_update.py keygen
IS_FROZEN = getattr(sys, "frozen", False)
APP_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))

# ------------------------------------------------------------------ paths
ROOT_DATA = Path.home() / ".nova_browser"


def _arg(flag):
    i = sys.argv.index(flag) if flag in sys.argv else -1
    return sys.argv[i + 1] if 0 <= i < len(sys.argv) - 1 else None


PROFILE = re.sub(r"[^A-Za-z0-9_-]", "", _arg("--profile") or "")[:24]      # multiple profiles
PROFILE_ID = "NovaMain" + (f"_{PROFILE}" if PROFILE else "")
DATA = ROOT_DATA / "profiles" / PROFILE if PROFILE else ROOT_DATA
FILTER_DIR = DATA / "filters"
USERSCRIPT_DIR = DATA / "userscripts"
MODS_DIR = DATA / "mods"
SOUND_DIR = DATA / "sounds"
DATA_TOR = DATA / "tor_data"
SHOT_DIR = Path.home() / "Pictures" / "Nova Screenshots"
for _d in (DATA, FILTER_DIR, USERSCRIPT_DIR, MODS_DIR, SOUND_DIR):
    _d.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = DATA / "settings.json"
BOOKMARKS_FILE = DATA / "bookmarks.json"
HISTORY_FILE = DATA / "history.json"
WORKSPACES_FILE = DATA / "workspaces.json"
SESSION_FILE = DATA / "session.json"
VAULT_FILE = DATA / "vault.json"
DOWNLOADS_LOG = DATA / "downloads.json"
QUAR_DIR = DATA / "quarantine"
VPN_DIR = DATA / "vpn"
EXT_DIR = DATA / "extensions"
for _d in (QUAR_DIR, VPN_DIR, EXT_DIR):
    _d.mkdir(parents=True, exist_ok=True)
FLOW_FILE = DATA / "flow.json"
PIN_FILE = DATA / "pinboards.json"
SEL_BAD = re.compile(r"[{};\\]|url\s*\(|@import|expression\s*\(", re.I)     # CSS-injection guard for filter lists
NEWTAB_BASE = QUrl.fromLocalFile(str(DATA) + "/")
NEWTAB_STR = NEWTAB_BASE.toString()
TOR_PORT_OWN = 9250


MAGIC = b"NOVA1"
KEY = None   # AES key, set after the master password is entered
SECURE_DEFAULTS = {"bookmarks.json": [], "history.json": [], "session.json": [], "workspaces.json": {},
                   "vault.json": {}, "downloads.json": [], "pinboards.json": {}, "flow.json": []}


def derive_key(pw, salt):
    return hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1, maxmem=2 ** 26, dklen=32)


def load_json(path, default):
    try:
        raw = Path(path).read_bytes()
        if raw.startswith(MAGIC):
            if KEY is None or not HAVE_CRYPTO:
                return default
            raw = AESGCM(KEY).decrypt(raw[5:17], raw[17:], None)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return default


def save_json(path, data):
    try:
        blob = json.dumps(data, indent=1).encode("utf-8")
        if KEY is not None and HAVE_CRYPTO and Path(path).name in SECURE_DEFAULTS:
            nonce = os.urandom(12)
            blob = MAGIC + nonce + AESGCM(KEY).encrypt(nonce, blob, None)
        Path(path).write_bytes(blob)
    except OSError:
        pass


# ------------------------------------------------------------------ settings
DEFAULTS = {
    # shields
    "shield": True, "https": True, "block_3p_cookies": True, "strip_params": True,
    "fingerprint": True, "cosmetic": True, "gpc": True, "userscripts": True,
    "shields_off": [],
    # performance
    "autosleep": True, "autosleep_min": 10, "ram_limit": False, "ram_mb": 2000,
    "cpu_limit": False, "cpu_pct": 70, "tab_limit": False, "tab_max": 10,
    "low_priority": False,
    # look & feel
    "theme": "GX Red", "search": "Brave Search", "force_dark": False,
    "sounds": False, "wallpaper": "", "restore_session": False, "volume": 70,
    "playlist": [],
    # security
    "popup_block": True, "dl_warn": True, "clear_on_exit": False, "paranoid": False,
    "spoof_tz": False, "webrtc_off": False, "spoof_screen": True, "js_off_hosts": [],
    "doh": "Off", "drm": True, "net_limit": False, "net_kbs": 2000,
    "tor_bridges": "", "tor_level": "Standard", "app_lock": False,
    "ai_enabled": False, "ai_model": "claude-sonnet-5-5",
    "welcomed": False, "auto_update": True,
    "bookmarks_bar": True, "block_autoplay": True, "cookie_auto": True, "gsb": False, "letterbox": False,
    "chroma": False, "site_perms": {}, "zoom": {}, "ext_disabled": [], "custom_apps": [],
    "sidebar_apps": ["WA", "TG", "DC", "MS", "SP", "YT", "TW", "X", "MT"],
    "panic_scorched": False, "panic_freespace": False,
    # antivirus / VPN / panic wipe
    "av_scan": True, "av_vt": False, "vpn_profiles": [], "vpn_active": "",
    "panic_downloads": True, "panic_screenshots": True, "panic_bookmarks": False,
    # advanced
    "proxy": "", "update_url": "", "update_pubkey": "",
}
SETTINGS = json.loads(json.dumps({**DEFAULTS, **load_json(SETTINGS_FILE, {})}))     # deep copy


def save_settings():
    save_json(SETTINGS_FILE, SETTINGS)


ENGINES = {
    "Brave Search": "https://search.brave.com/search?q=",
    "DuckDuckGo": "https://duckduckgo.com/?q=",
    "Ecosia": "https://www.ecosia.org/search?q=",
    "Google": "https://www.google.com/search?q=",
}


def search_url():
    return ENGINES.get(SETTINGS["search"], ENGINES["Brave Search"])


THEMES = {  # name: (accent, background)
    "GX Red": ("#fa1e4e", "#14141c"),
    "Cyber Blue": ("#00d9ff", "#0b1220"),
    "Toxic Green": ("#7cff00", "#0e140b"),
    "Violet": ("#a855f7", "#150f1f"),
    "Mono": ("#e5e5e5", "#101010"),
}


def theme():
    return THEMES.get(SETTINGS["theme"], THEMES["GX Red"])


ICON_DIR = DATA / "icons"
ICON_DIR.mkdir(parents=True, exist_ok=True)
INSTANCE_NAME = "NovaBrowserSingleInstance" + (f"_{PROFILE}" if PROFILE else "")
BRAND = {"WA": "#25D366", "TG": "#229ED9", "DC": "#5865F2", "MS": "#0084FF", "SP": "#1DB954",
         "YT": "#FF0033", "TW": "#9146FF", "X": "#15151b", "MT": "#1D76BA"}

_L = '<path d="{}"/>'
ICON_PATHS = {
    "back": '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>',
    "forward": '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
    "reload": '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
    "home": '<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/>',
    "star": '<path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "shield-off": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m2 2 20 20"/>',
    "shield-check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "menu": '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
    "plus": '<path d="M5 12h14"/><path d="M12 5v14"/>',
    "x": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    "lock": '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "unlock": '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
    "sliders": '<path d="M21 4h-7"/><path d="M10 4H3"/><path d="M21 12h-9"/><path d="M8 12H3"/><path d="M21 20h-5"/><path d="M12 20H3"/><path d="M14 2v4"/><path d="M8 10v4"/><path d="M16 18v4"/>',
    "music": '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    "panel": '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M15 3v18"/>',
    "trash": '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    "camera": '<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3z"/><circle cx="12" cy="13" r="3"/>',
    "book": '<path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/>',
    "gamepad": '<path d="M6 12h4"/><path d="M8 10v4"/><path d="M15 13h.01"/><path d="M18 11h.01"/><rect width="20" height="12" x="2" y="6" rx="2"/>',
    "pip": '<path d="M8 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3"/><rect width="10" height="7" x="12" y="4" rx="1"/>',
    "sparkles": '<path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3z"/>',
    "key": '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
    "network": '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "alert": '<path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
}
_ICON_CACHE = {}


def svg_icon(name, color="#cfd0dc", size=20, fill=False):
    key = (name, color, size, fill)
    if key in _ICON_CACHE:
        return _ICON_CACHE[key]
    body = ICON_PATHS.get(name, "")
    ic = QIcon()
    if HAVE_SVG and body:
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="{color if fill else "none"}" '
               f'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{body}</svg>')
        pm = QPixmap(size * 2, size * 2)
        pm.setDevicePixelRatio(2)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        QSvgRenderer(QByteArray(svg.encode())).render(p, QRectF(0, 0, size, size))
        p.end()
        ic = QIcon(pm)
    _ICON_CACHE[key] = ic
    return ic


def badge_icon(letter, color, size=30):
    pm = QPixmap(size * 2, size * 2)
    pm.setDevicePixelRatio(2)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(1, 1, size - 2, size - 2), 9, 9)
    f = p.font()
    f.setBold(True)
    f.setPixelSize(int(size * 0.42))
    p.setFont(f)
    p.setPen(QColor("#ffffff"))
    p.drawText(QRectF(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, letter)
    p.end()
    return QIcon(pm)


def ensure_ui_assets():
    """Close-button images referenced from the stylesheet."""
    for name, col in (("close", "#9a9aa8"), ("close-hover", "#ffffff")):
        svg_icon("x", col, 14).pixmap(14, 14).save(str(ICON_DIR / f"{name}.png"))


def make_palette(acc, bg):
    c, R, pal = QColor(bg), QPalette.ColorRole, QPalette()
    fg = QColor("#e8e8f0")
    on_acc = QColor("#000000" if QColor(acc).lightness() > 150 else "#ffffff")
    for role, col in ((R.Window, c), (R.WindowText, fg), (R.Base, c.lighter(150)), (R.AlternateBase, c.lighter(125)),
                      (R.Text, fg), (R.Button, c.lighter(135)), (R.ButtonText, fg), (R.ToolTipBase, c.lighter(170)),
                      (R.ToolTipText, fg), (R.Highlight, QColor(acc)), (R.HighlightedText, on_acc),
                      (R.PlaceholderText, QColor("#8a8a99")), (R.Link, QColor(acc))):
        pal.setColor(role, col)
    return pal


def make_qss(acc, bg):
    c = QColor(bg)
    strip, chrome = c.darker(150).name(), c.lighter(112).name()
    field, hover, edge = c.lighter(150).name(), c.lighter(135).name(), c.lighter(190).name()
    fg = "#000000" if QColor(acc).lightness() > 150 else "#ffffff"
    ic = ICON_DIR.as_posix()
    return f"""
QMainWindow, QDialog {{ background:{bg}; }}
QToolTip {{ background:{hover}; color:#fff; border:1px solid {edge}; padding:4px 8px; }}
QDockWidget {{ font-weight:600; }}
QDockWidget::title {{ background:{strip}; padding:9px 12px; }}
QDockWidget > QWidget {{ background:{bg}; }}
QWidget#tabstrip {{ background:{strip}; }}
QTabBar {{ background:transparent; }}
QTabBar::tab {{ background:transparent; color:#a3a3b3; padding:8px 12px; margin:0 1px; min-width:80px; max-width:220px;
  border-top-left-radius:10px; border-top-right-radius:10px; }}
QTabBar::tab:hover {{ background:{hover}; color:#ffffff; }}
QTabBar::tab:selected {{ background:{chrome}; color:#ffffff; }}
QTabBar::close-button {{ image:url({ic}/close.png); subcontrol-position:right; border-radius:4px; padding:2px; }}
QTabBar::close-button:hover {{ image:url({ic}/close-hover.png); background:{edge}; }}
QTabBar QToolButton {{ background:{hover}; border:none; }}
QToolButton#newtab {{ border-radius:14px; padding:5px; margin:0 4px 4px 4px; }}
QToolBar#nav {{ background:{chrome}; border:none; padding:6px 8px; spacing:5px; }}
QToolBar#sidebar {{ background:{strip}; border:none; padding:8px 5px; spacing:8px; }}
QToolBar#bmbar {{ background:{chrome}; border:none; border-top:1px solid {strip}; padding:2px 8px; spacing:2px; }}
QToolBar#bmbar QToolButton {{ padding:3px 9px; font-size:12px; color:#c2c3d0; }}
QToolBar QToolButton, QToolButton {{ background:transparent; border:none; border-radius:9px; padding:6px; }}
QToolBar QToolButton:hover, QToolButton:hover {{ background:{hover}; }}
QToolBar QToolButton:pressed, QToolButton:pressed {{ background:{edge}; }}
QToolButton::menu-indicator {{ image:none; }}
QToolButton#shield {{ padding:6px 10px; font-weight:600; }}
QLineEdit#omnibox {{ background:{field}; border:1px solid transparent; border-radius:18px; padding:7px 14px; font-size:14px;
  selection-background-color:{acc}; selection-color:{fg}; }}
QLineEdit#omnibox:hover {{ background:{hover}; }}
QLineEdit#omnibox:focus {{ background:{strip}; border:1px solid {acc}; }}
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextBrowser {{ background:{field}; border:1px solid {edge}; border-radius:8px; padding:5px 9px; }}
QLineEdit:focus, QPlainTextEdit:focus {{ border:1px solid {acc}; }}
QComboBox::drop-down {{ border:none; width:22px; }}
QPushButton {{ background:{hover}; border:1px solid {edge}; border-radius:8px; padding:7px 14px; }}
QPushButton:hover {{ background:{acc}; color:{fg}; border-color:{acc}; }}
QCheckBox {{ spacing:9px; padding:3px 0; }}
QCheckBox::indicator {{ width:16px; height:16px; border-radius:4px; }}
QCheckBox::indicator:checked {{ background:{acc}; border:1px solid {acc}; }}
QCheckBox::indicator:unchecked {{ background:{field}; border:1px solid {edge}; }}
QGroupBox {{ border:1px solid {edge}; border-radius:10px; margin-top:14px; padding:14px 8px 8px 8px; }}
QGroupBox::title {{ subcontrol-origin:margin; left:12px; color:{acc}; font-weight:600; }}
QMenu {{ background:{hover}; border:1px solid {edge}; border-radius:10px; padding:6px; }}
QMenu::item {{ padding:7px 26px 7px 14px; border-radius:6px; }}
QMenu::item:selected {{ background:{acc}; color:{fg}; }}
QMenu::item:disabled {{ color:#7d7d90; }}
QMenu::separator {{ height:1px; background:{edge}; margin:5px 8px; }}
QListWidget {{ background:{field}; border:1px solid {edge}; border-radius:8px; }}
QListWidget::item {{ padding:6px; border-radius:6px; }}
QListWidget::item:selected {{ background:{acc}; color:{fg}; }}
QSlider::groove:horizontal {{ height:4px; background:{edge}; border-radius:2px; }}
QSlider::handle:horizontal {{ background:{acc}; width:14px; margin:-6px 0; border-radius:7px; }}
QScrollBar:vertical {{ background:transparent; width:10px; margin:0; }}
QScrollBar::handle:vertical {{ background:{edge}; border-radius:5px; min-height:30px; }}
QScrollBar:horizontal {{ background:transparent; height:10px; margin:0; }}
QScrollBar::handle:horizontal {{ background:{edge}; border-radius:5px; min-width:30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
QStatusBar {{ background:{strip}; color:#9a9aad; }}
QScrollArea {{ border:0; }}
"""


def apply_theme(app):
    ensure_ui_assets()
    acc, bg = theme()
    app.setPalette(make_palette(acc, bg))
    app.setStyleSheet(make_qss(acc, bg))


def send_to_running(urls):
    """If Nova is already running, hand it the links and report True (single-instance behaviour)."""
    s = QLocalSocket()
    s.connectToServer(INSTANCE_NAME)
    if s.waitForConnected(300):
        s.write(("\n".join(urls) or "focus").encode())
        s.flush()
        s.waitForBytesWritten(1000)
        s.disconnectFromServer()
        return True
    return False


INSTANCE_SERVER = []


def start_instance_server(win):
    server = QLocalServer()
    QLocalServer.removeServer(INSTANCE_NAME)
    server.listen(INSTANCE_NAME)

    def on_conn():
        sock = server.nextPendingConnection()
        if sock is None:
            return
        sock.waitForReadyRead(500)
        for u in bytes(sock.readAll()).decode(errors="ignore").split("\n"):
            if u.lower().startswith(("http://", "https://", "file://")):
                win.new_tab(u)
        if win.isMinimized():
            win.showNormal()
        win.raise_()
        win.activateWindow()
        sock.disconnectFromServer()
    server.newConnection.connect(on_conn)
    return server


# ------------------------------------------------------------------ filter lists
BUILTIN_BLOCK = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "googletagmanager.com", "adservice.google.com",
    "connect.facebook.net", "scorecardresearch.com", "outbrain.com", "taboola.com",
    "criteo.com", "adnxs.com", "hotjar.com", "quantserve.com", "amazon-adsystem.com",
    "moatads.com", "pubmatic.com", "rubiconproject.com", "openx.net", "adsrvr.org",
    "casalemedia.com", "mixpanel.com", "segment.io", "fullstory.com", "mouseflow.com",
    "bat.bing.com", "ads.linkedin.com", "analytics.tiktok.com", "static.ads-twitter.com",
}
BUILTIN_COSMETIC = [
    ".adsbygoogle", "ins.adsbygoogle", "[id^='google_ads']", "[id^='div-gpt-ad']",
    ".ad-banner", ".ad-container", ".advert", ".advertisement", "#ad-container",
    "[class*='sponsored-ad']", ".sponsored-content", "[aria-label='advertisement']",
]
BAD_SEL = (":-abp-", ":has-text", ":xpath", ":matches", ":contains", ":style(",
           ":remove(", ":upward", ":nth-ancestor", ":min-text", ":watch-attr", ":others")
TRACKING_PARAMS = {"fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "mc_eid",
                   "igshid", "yclid", "_hsenc", "_hsmi", "mkt_tok", "vero_id", "twclid",
                   "ttclid", "wickedid", "oly_enc_id", "oly_anon_id", "ref_src", "s_cid"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class Filters:
    """Parses Adblock-format lists (EasyList etc.) dropped in ~/.nova_browser/filters/*.txt"""

    def __init__(self):
        self.block, self.generic, self.specific, self.hosts = set(), list(BUILTIN_COSMETIC), {}, set()
        self.badurls = set()

    def load(self):
        block, generic, specific, hosts = set(), list(BUILTIN_COSMETIC), {}, set()
        for f in sorted(FILTER_DIR.glob("*.txt")):
            try:
                lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for ln in lines:
                ln = ln.strip()
                if not ln or ln[0] in "![#" or ln.startswith("@@"):
                    if not (ln.startswith("##") or ln.startswith("#@")):
                        continue
                parts = ln.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") and "." in parts[1]:
                    hosts.add(parts[1].lower())        # hosts-format (malware / ad lists): blocks even top-level
                    continue
                if ln.startswith("||"):
                    rule, opts = ln[2:], ""
                    if "$" in rule:
                        rule, opts = rule.split("$", 1)
                    if opts and set(opts.split(",")) - {"third-party", "3p"}:
                        continue
                    rule = rule[:-1] if rule.endswith("^") else rule
                    if "." in rule and re.fullmatch(r"[a-z0-9.-]+", rule, re.I):
                        block.add(rule.lower())
                elif "##" in ln and "#@#" not in ln:
                    dom, sel = ln.split("##", 1)
                    if not sel or any(b in sel for b in BAD_SEL) or SEL_BAD.search(sel):
                        continue
                    if not dom:
                        if len(generic) < 15000:
                            generic.append(sel)
                    elif "~" not in dom:
                        for d in dom.split(","):
                            lst = specific.setdefault(d.lower(), [])
                            if len(lst) < 400:
                                lst.append(sel)
        bad = set()
        for f in FILTER_DIR.glob("*.urls"):
            try:
                for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                    ln = ln.strip().lower()
                    if ln.startswith("http"):
                        bad.add(ln.split("://", 1)[1].split("?")[0].split("#")[0].rstrip("/"))
            except OSError:
                pass
        self.badurls = bad
        self.block, self.generic, self.specific, self.hosts = block, generic, specific, hosts


FILTERS = Filters()


# ------------------------------------------------------------------ shields (request interceptor)
def host_in(host, pool):
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in pool:
            return True
    return False


class Shields(QWebEngineUrlRequestInterceptor):
    blocked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.count = 0
        self.off = set()
        self.allblock = set(BUILTIN_BLOCK)
        self.hostsblock = set()
        self.badurls = set()

    def interceptRequest(self, info):
        S = SETTINGS
        if not S["shield"]:
            return
        url = info.requestUrl()
        host = url.host().lower()
        first = info.firstPartyUrl().host().lower()
        if (first and host_in(first, self.off)) or (host and host_in(host, self.off)):
            return
        main = info.resourceType() == QWebEngineUrlRequestInfo.ResourceType.ResourceTypeMainFrame
        if S["gpc"]:
            info.setHttpHeader(b"Sec-GPC", b"1")
            info.setHttpHeader(b"DNT", b"1")
        if main and self.badurls and (host + url.path().lower().rstrip("/")) in self.badurls:
            info.block(True)                      # known phishing page
            self.count += 1
            self.blocked.emit()
            return
        if host and (host_in(host, self.hostsblock) or (not main and host_in(host, self.allblock))):
            info.block(True)
            self.count += 1
            self.blocked.emit()
            return
        changed = False
        if main and S["strip_params"] and url.hasQuery():
            items = QUrlQuery(url).queryItems()
            kept = [(k, v) for k, v in items
                    if k.lower() not in TRACKING_PARAMS and not k.lower().startswith("utm_")]
            if len(kept) != len(items):
                q = QUrlQuery()
                for k, v in kept:
                    q.addQueryItem(k, v)
                url.setQuery(q)
                changed = True
        if (S["https"] and url.scheme() == "http" and host not in LOCAL_HOSTS
                and url.port() in (-1, 80)):
            url.setScheme("https")
            if url.port() == 80:
                url.setPort(-1)
            changed = True
        if changed:
            info.redirect(url)


SHIELDS = Shields()
SHIELDS.off = set(SETTINGS["shields_off"])

# ------------------------------------------------------------------ injected scripts
FP_JS = r"""(()=>{const OFF=__OFF__,F=__FLAGS__,h=location.hostname;
if(OFF.some(x=>h===x||h.endsWith('.'+x)))return;
const s=(Math.random()*255)|0;
const jit=px=>{for(let i=0;i<px.length;i+=4*89){px[i]=(px[i]+(s&3))&255;}};
try{const gid=CanvasRenderingContext2D.prototype.getImageData;
CanvasRenderingContext2D.prototype.getImageData=function(...a){const d=gid.apply(this,a);jit(d.data);return d;};
const tdu=HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL=function(...a){try{const c=this.getContext('2d');
if(c&&this.width&&this.height){const d=gid.call(c,0,0,this.width,this.height);jit(d.data);c.putImageData(d,0,0);}}catch(e){}
return tdu.apply(this,a);};}catch(e){}
try{const g=AudioBuffer.prototype.getChannelData;AudioBuffer.prototype.getChannelData=function(...a){
const d=g.apply(this,a);for(let i=0;i<d.length;i+=211)d[i]+=(s%50)*1e-8;return d;};}catch(e){}
try{const g=AnalyserNode.prototype.getFloatFrequencyData;AnalyserNode.prototype.getFloatFrequencyData=function(a){
g.call(this,a);for(let i=0;i<a.length;i+=7)a[i]+=(s%50)*1e-6;};}catch(e){}
try{Object.defineProperty(Navigator.prototype,'hardwareConcurrency',{get:()=>4});
Object.defineProperty(Navigator.prototype,'deviceMemory',{get:()=>8});
if(navigator.getBattery)Object.defineProperty(Navigator.prototype,'getBattery',{value:undefined});}catch(e){}
try{const m=navigator.userAgent.match(/Chrome\/(\d+)/),v=m?m[1]:'120';
const br=[{brand:'Chromium',version:v},{brand:'Google Chrome',version:v},{brand:'Not.A/Brand',version:'99'}];
const d={brands:br,mobile:false,platform:'Windows',
getHighEntropyValues:()=>Promise.resolve({brands:br,mobile:false,platform:'Windows',platformVersion:'10.0.0',architecture:'x86',bitness:'64',model:'',uaFullVersion:v+'.0.0.0'}),
toJSON:()=>({brands:br,mobile:false,platform:'Windows'})};
Object.defineProperty(Navigator.prototype,'userAgentData',{get:()=>d});}catch(e){}
if(F.screen){
try{for(const C of [window.WebGLRenderingContext,window.WebGL2RenderingContext].filter(Boolean)){const gp=C.prototype.getParameter;
C.prototype.getParameter=function(p){if(p===37445)return 'Google Inc. (Intel)';
if(p===37446)return 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';return gp.call(this,p);};}}catch(e){}
try{const S={width:1920,height:1080,availWidth:1920,availHeight:1040,colorDepth:24,pixelDepth:24};
for(const k in S)Object.defineProperty(Screen.prototype,k,{get:()=>S[k]});}catch(e){}}
if(F.tz){try{Date.prototype.getTimezoneOffset=function(){return 0;};
const ro=Intl.DateTimeFormat.prototype.resolvedOptions;
Intl.DateTimeFormat.prototype.resolvedOptions=function(){const o=ro.call(this);o.timeZone='UTC';return o;};}catch(e){}}
if(F.rtc){for(const n of ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription']){try{window[n]=undefined;}catch(e){}}
try{Object.defineProperty(Navigator.prototype,'mediaDevices',{get:()=>undefined});}catch(e){}}
})();"""

COSMETIC_JS = r"""(()=>{const OFF=__OFF__,G=__GENERIC__,D=__SPECIFIC__,h=location.hostname;
if(OFF.some(x=>h===x||h.endsWith('.'+x)))return;
let sel=G.slice();
for(const k in D){if(h===k||h.endsWith('.'+k))sel=sel.concat(D[k]);}
if(!sel.length)return;
const css=sel.map(x=>x+'{display:none!important}').join('\n');
const add=()=>{const st=document.createElement('style');st.textContent=css;(document.head||document.documentElement).appendChild(st);};
if(document.documentElement)add();else new MutationObserver((m,o)=>{if(document.documentElement){o.disconnect();add();}}).observe(document,{childList:true});
})();"""

READER_JS = r"""(()=>{
const score=e=>[...e.querySelectorAll('p')].reduce((n,p)=>n+p.innerText.length,0);
const cands=[...document.querySelectorAll('article,main,[role=main],.post,.entry-content,.article,#content,.content,#main')];
let best=document.body,bs=score(document.body)*0.6;
for(const c of cands){const s=score(c);if(s>bs){best=c;bs=s;}}
const clone=best.cloneNode(true);
clone.querySelectorAll('script,style,nav,aside,footer,form,iframe,noscript,button,svg,[class*=share],[class*=comment],[class*=related],[class*=newsletter],[id*=comment]').forEach(e=>e.remove());
const title=document.title.replace(/</g,'&lt;');
document.head.innerHTML='<meta charset="utf-8"><title>'+title+'</title><style>body{max-width:720px;margin:40px auto;padding:0 20px;font:19px/1.7 Georgia,serif;background:#16161d;color:#e6e6ee}a{color:__ACC__}img,video{max-width:100%;height:auto}h1,h2,h3{font-family:Segoe UI,sans-serif;line-height:1.25}pre{overflow:auto;background:#0d0d12;padding:12px}blockquote{border-left:3px solid __ACC__;margin-left:0;padding-left:16px;color:#aaa}</style>';
document.body.removeAttribute('class');document.body.removeAttribute('style');
document.body.innerHTML='<h1>'+title+'</h1>'+clone.innerHTML;
})();"""

SPEED_HTML = """<html><head><meta charset="utf-8"><title>New Tab</title></head>
<body style="margin:0;min-height:100vh;background:__BG__;color:#eee;font-family:Segoe UI,system-ui,sans-serif;text-align:center">
<div style="position:fixed;inset:0;background:radial-gradient(circle at 50% -10%,__ACC__33,transparent 55%);z-index:-1"></div>
<div style="padding-top:11vh">
<div id="clock" style="font-size:64px;font-weight:200;letter-spacing:2px"></div>
<div id="hi" style="color:#9a9aad;margin:4px 0 26px"></div>
<form action="__ACTION__"><input name="q" autofocus placeholder="Search privately or type an address"
style="width:520px;max-width:84vw;padding:14px 22px;border-radius:28px;border:1px solid #33333f;background:rgba(20,20,28,.85);color:#fff;font-size:16px;outline:none"></form>
<div style="margin-top:46px;display:flex;gap:26px;justify-content:center;flex-wrap:wrap;max-width:760px;margin-left:auto;margin-right:auto">__TILES__</div>
<p style="margin-top:56px;color:#7d7d90;font-size:13px">🛡 __STATS__</p></div>
<script>const t=()=>{const d=new Date();document.getElementById('clock').textContent=d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const h=d.getHours();document.getElementById('hi').textContent=h<12?'Good morning':h<18?'Good afternoon':'Good evening';};t();setInterval(t,20000);</script>
<style>a{color:#ddd;text-decoration:none;font-size:12px;width:84px}
.t{width:64px;height:64px;border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700;color:#fff;margin:auto auto 8px;box-shadow:0 4px 14px rgba(0,0,0,.35)}
a:hover .t{transform:translateY(-3px);transition:.15s}</style></body></html>"""

WELCOME_HTML = """<html><head><meta charset="utf-8"><title>Welcome to Nova</title></head>
<body style="margin:0;background:#14141c;color:#eee;font-family:Segoe UI,system-ui,sans-serif">
<div style="max-width:880px;margin:0 auto;padding:9vh 24px">
<h1 style="font-size:44px;margin:0 0 6px"><span style="color:#fa1e4e">Nova</span> is ready.</h1>
<p style="color:#9a9aad;font-size:18px;margin:0 0 34px">Private by default. Here is what you got.</p>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px">
<div class="c"><b>🛡 Shields are on</b><p>Ads, trackers, fingerprinting and third-party cookies are blocked. Click the shield in the toolbar to tune a site.</p></div>
<div class="c"><b>🧅 Tor &amp; 🔒 VPN</b><p>Open a Tor window from the toolbar, or add your VPN provider in the VPN panel.</p></div>
<div class="c"><b>🚨 Panic Wipe</b><p>Press <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Backspace</kbd> to erase your traces and close instantly.</p></div>
<div class="c"><b>🦠 Download scanning</b><p>Every download is checked with Microsoft Defender before you open it.</p></div></div>
<p style="margin-top:34px;color:#9a9aad">Test your protection: <a href="https://coveryourtracks.eff.org">Cover Your Tracks</a> ·
<a href="https://ipleak.net">IP &amp; DNS leak test</a> · Open the sliders icon in the sidebar for Settings.</p></div>
<style>.c{background:#1d1d28;border:1px solid #2a2a38;border-radius:14px;padding:6px 20px 12px}.c p{color:#a9a9b8;line-height:1.5}
a{color:#fa1e4e}kbd{background:#2a2a38;border-radius:4px;padding:1px 6px}</style></body></html>"""

TOR_WAIT_HTML = ("<body style='background:#14141c;color:#eee;font-family:Segoe UI;text-align:center;"
                 "padding-top:20vh'><h1 style='color:#fa1e4e'>🧅 Connecting to Tor…</h1>"
                 "<p>Nothing leaves your machine until the circuit is built.</p></body>")


def load_userscripts():
    """Tampermonkey-style .user.js files (@match/@include/@exclude/@run-at; no GM_* APIs)."""
    out = []
    P = QWebEngineScript.InjectionPoint
    for f in sorted(USERSCRIPT_DIR.glob("*.user.js")):
        try:
            src = f.read_text(encoding="utf-8")
        except OSError:
            continue
        matches, excludes, run = [], [], "document-end"
        m = re.search(r"// ==UserScript==(.*?)// ==/UserScript==", src, re.S)
        if m:
            for ln in m.group(1).splitlines():
                mm = re.match(r"\s*//\s*@(\S+)\s+(.*)", ln)
                if not mm:
                    continue
                k, v = mm.group(1), mm.group(2).strip()
                if k in ("match", "include"):
                    matches.append(v)
                elif k in ("exclude", "exclude-match"):
                    excludes.append(v)
                elif k == "run-at":
                    run = v

        def rx(p):
            return ".*" if p == "<all_urls>" else "^" + re.escape(p).replace(r"\*", ".*") + "$"

        wrapper = ("(function(){const M=%s,X=%s,u=location.href;"
                   "if(M.length&&!M.some(p=>new RegExp(p).test(u)))return;"
                   "if(X.some(p=>new RegExp(p).test(u)))return;\n%s\n})();"
                   % (json.dumps([rx(p) for p in matches]), json.dumps([rx(p) for p in excludes]), src))
        point = (P.DocumentCreation if run == "document-start"
                 else P.Deferred if run == "document-idle" else P.DocumentReady)
        out.append((f.stem, wrapper, point))
    return out


def load_mods():
    """GX-style 'mods': any .css in ~/.nova_browser/mods is applied to every page."""
    out = []
    for f in sorted(MODS_DIR.glob("*.css")):
        try:
            css = f.read_text(encoding="utf-8")
        except OSError:
            continue
        js = ("(()=>{const a=()=>{const s=document.createElement('style');s.textContent=%s;"
              "(document.head||document.documentElement).appendChild(s)};"
              "if(document.documentElement)a();else document.addEventListener('DOMContentLoaded',a)})();"
              % json.dumps(css))
        out.append((f.stem, js))
    return out


def ensure_samples():
    s = USERSCRIPT_DIR / "sample-hello.user.js"
    if not s.exists() and not any(USERSCRIPT_DIR.glob("*.user.js")):
        s.write_text("// ==UserScript==\n// @name  Hello\n// @match https://example.com/*\n"
                     "// @run-at document-end\n// ==/UserScript==\n"
                     "console.log('Nova userscript running on', location.href);\n"
                     "document.title = '★ ' + document.title;\n", encoding="utf-8")
    m = MODS_DIR / "sample.css.txt"
    if not m.exists():
        m.write_text("/* Rename to anything.css - applied to every page. Example:\n"
                     "::selection { background:#fa1e4e; color:#fff; }\n*/\n", encoding="utf-8")


def make_sounds():
    specs = {"click": [(880, .05)], "open": [(660, .06), (990, .09)], "close": [(990, .06), (660, .09)]}
    for name, tones in specs.items():
        p = SOUND_DIR / f"{name}.wav"
        if p.exists():
            continue
        frames = bytearray()
        for freq, dur in tones:
            n = int(44100 * dur)
            for i in range(n):
                frames += struct.pack("<h", int(11000 * (1 - i / n) * math.sin(2 * math.pi * freq * i / 44100)))
        with wave.open(str(p), "wb") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(44100); w.writeframes(bytes(frames))


# ------------------------------------------------------------------ tor helpers
def find_tor_exe():
    names = ("tor.exe", "tor")
    bases = (APP_DIR / "tor", APP_DIR / "tor" / "tor", Path(sys.executable).parent / "tor",
             Path(sys.executable).parent / "tor" / "tor")
    for b in bases:
        for n in names:
            if (b / n).is_file():
                return b / n
    found = shutil.which("tor")
    return Path(found) if found else None


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def pick_tor_port():
    exe = find_tor_exe()
    if exe:
        return TOR_PORT_OWN, exe
    for p in (9150, 9050):
        if port_open(p):
            return p, None
    return None, None


# ------------------------------------------------------------------ misc helpers
class FetchThread(QThread):
    """HTTPS download to a file, optional SHA-256 verification."""
    done = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, url, dest, sha256=None):
        super().__init__()
        self.url, self.dest, self.sha256 = url, Path(dest), sha256

    def run(self):
        try:
            if not self.url.startswith("https://"):
                raise ValueError("HTTPS is required")
            req = urllib.request.Request(self.url, headers={"User-Agent": f"Nova/{VERSION}"})
            h = hashlib.sha256()
            size = 0
            with SAFE_OPENER.open(req, timeout=30) as r, open(self.dest, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk); h.update(chunk)
                    size += len(chunk)
                    if size > 600 * 1024 * 1024:
                        raise ValueError("download too large")
            if self.sha256 and h.hexdigest().lower() != self.sha256.lower():
                self.dest.unlink(missing_ok=True)
                raise ValueError("checksum mismatch - download discarded")
            self.done.emit(str(self.dest))
        except Exception as e:
            self.failed.emit(str(e))


def open_folder(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        os.startfile(str(path))
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def is_blank(url):
    s = url.toString()
    return s.startswith("about:") or s.startswith("data:") or s.startswith(NEWTAB_STR)


def make_profile(private):
    otr = private or SETTINGS["paranoid"]
    profile = QWebEngineProfile() if otr else QWebEngineProfile(PROFILE_ID)
    # don't announce "QtWebEngine" in the User-Agent; fixed Accept-Language
    profile.setHttpUserAgent(re.sub(r"\s*QtWebEngine/[\d.]+", "", profile.httpUserAgent()))
    profile.setHttpAcceptLanguage("en-US,en;q=0.9")
    profile.setUrlRequestInterceptor(SHIELDS)
    profile.cookieStore().setCookieFilter(
        lambda req: not (SETTINGS["block_3p_cookies"] and SETTINGS["shield"] and req.thirdParty))
    if not otr and SETTINGS["clear_on_exit"]:
        profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
        profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
    if hasattr(profile, "setPersistentPermissionsPolicy"):
        profile.setPersistentPermissionsPolicy(QWebEngineProfile.PersistentPermissionsPolicy.AskEveryTime)
    s = profile.settings()
    A = QWebEngineSettings.WebAttribute
    s.setAttribute(A.FullScreenSupportEnabled, True)
    s.setAttribute(A.ScrollAnimatorEnabled, True)
    for name, val in (("PluginsEnabled", False), ("HyperlinkAuditingEnabled", False),
                      ("DnsPrefetchEnabled", False), ("WebRTCPublicInterfacesOnly", True),
                      ("AllowRunningInsecureContent", False), ("JavascriptCanAccessClipboard", False),
                      ("AllowGeolocationOnInsecureOrigins", False),
                      ("PlaybackRequiresUserGesture", bool(SETTINGS["block_autoplay"])), ("PdfViewerEnabled", True)):
        attr = getattr(A, name, None)
        if attr is not None:
            s.setAttribute(attr, val)
    dark = getattr(A, "ForceDarkMode", None)
    if dark is not None:
        s.setAttribute(dark, bool(SETTINGS["force_dark"]))
    return profile


# ------------------------------------------------------------------ views / docks
class NovaPage(QWebEnginePage):
    def __init__(self, profile, parent, browser):
        super().__init__(profile, parent)
        self.browser = browser

    def acceptNavigationRequest(self, url, nav_type, is_main):
        if is_main:
            scheme = url.scheme().lower()
            if scheme in ("mailto", "tel"):
                QDesktopServices.openUrl(url)
                return False
            if scheme not in ALLOWED_SCHEMES:       # ms-msdt:, search-ms:, vbscript: ... are never launched
                self.browser.statusBar().showMessage(f"Blocked unsafe link type: {scheme}:", 6000)
                return False
            if scheme == "file" and nav_type == QWebEnginePage.NavigationType.NavigationTypeLinkClicked:
                self.browser.statusBar().showMessage("Web pages can't open local files", 6000)
                return False
            A = QWebEngineSettings.WebAttribute
            st = self.settings()
            st.setAttribute(A.JavascriptEnabled, self.browser.js_allowed(url.host()))   # decided BEFORE the page loads
            webgl = getattr(A, "WebGLEnabled", None)
            if webgl is not None:
                st.setAttribute(webgl, not (self.browser.tor and SETTINGS["tor_level"] in ("Safer", "Safest")))
        return super().acceptNavigationRequest(url, nav_type, is_main)

    def chooseFiles(self, mode, old_files, accepted):
        return self.browser.easy_files(mode == QWebEnginePage.FileSelectionMode.FileSelectOpenMultiple)


class View(QWebEngineView):
    def __init__(self, browser, profile):
        super().__init__()
        self.browser = browser
        self.setPage(NovaPage(profile, self, browser))

    def createWindow(self, _type):
        return self.browser.new_tab(raw=True)


class Tab(View):
    def __init__(self, browser, profile):
        super().__init__(browser, profile)
        self.last_active = time.time()
        self.pinned = False
        self.island = None


class SidePanel(QDockWidget):
    """Opera-style sidebar messengers / split view: a second web view docked beside the tab."""

    def __init__(self, browser):
        super().__init__("Side panel", browser)
        self.browser = browser
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(4, 4, 4, 4)
        row = QHBoxLayout()
        self.url = QLineEdit(placeholderText="Address")
        self.url.returnPressed.connect(lambda: self.view.setUrl(QUrl.fromUserInput(self.url.text())))
        mirror = QPushButton("⇆ tab")
        mirror.setToolTip("Load the current tab here (split view)")
        mirror.clicked.connect(lambda _=False: self.view.setUrl(browser.cur().url()))
        row.addWidget(self.url); row.addWidget(mirror)
        lay.addLayout(row)
        self.view = View(browser, browser.profile)
        self.view.page().proxyAuthenticationRequired.connect(browser.on_proxy_auth)
        self.view.setMinimumWidth(380)
        self.view.urlChanged.connect(lambda u: self.url.setText("" if is_blank(u) else u.toString()))
        lay.addWidget(self.view)
        self.setWidget(w)
        self.hide()

    def open(self, url):
        self.show()
        self.view.setUrl(QUrl(url))


class MusicDock(QDockWidget):
    """Local music player (mp3/flac/wav/ogg/m4a) + shortcuts to streaming sites."""

    def __init__(self, browser):
        super().__init__("Music", browser)
        w = QWidget(); lay = QVBoxLayout(w)
        self.setWidget(w)
        self.cur_row = -1
        if not HAVE_AUDIO:
            lay.addWidget(QLabel("Qt Multimedia isn't available in this build."))
            return
        self.player = QMediaPlayer(self)
        self.audio = QAudioOutput(self)
        self.player.setAudioOutput(self.audio)
        self.audio.setVolume(SETTINGS["volume"] / 100)
        self.now = QLabel("Nothing playing")
        lay.addWidget(self.now)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda it: self.play_row(self.list.row(it)))
        lay.addWidget(self.list)
        row = QHBoxLayout()
        for t, f in (("⏮", self.prev), ("⏯", self.toggle), ("⏭", self.next),
                     ("➕", self.add_files), ("🗑", self.remove_sel)):
            b = QPushButton(t); b.clicked.connect(lambda _=False, f=f: f()); row.addWidget(b)
        lay.addLayout(row)
        self.pos = QSlider(Qt.Orientation.Horizontal)
        self.pos.sliderMoved.connect(self.player.setPosition)
        lay.addWidget(self.pos)
        lay.addWidget(QLabel("Volume"))
        self.vol = QSlider(Qt.Orientation.Horizontal)
        self.vol.setRange(0, 100); self.vol.setValue(SETTINGS["volume"])
        self.vol.valueChanged.connect(self.set_vol)
        lay.addWidget(self.vol)
        lay.addWidget(QLabel("Streaming (opens in side panel):"))
        row2 = QHBoxLayout()
        for name, url in (("Spotify", "https://open.spotify.com"), ("YT Music", "https://music.youtube.com"),
                          ("SoundCloud", "https://soundcloud.com")):
            b = QPushButton(name); b.clicked.connect(lambda _=False, u=url: browser.open_panel(u)); row2.addWidget(b)
        lay.addLayout(row2)
        self.player.positionChanged.connect(lambda p: None if self.pos.isSliderDown() else self.pos.setValue(p))
        self.player.durationChanged.connect(lambda d: self.pos.setRange(0, d))
        self.player.mediaStatusChanged.connect(
            lambda st: self.next() if st == QMediaPlayer.MediaStatus.EndOfMedia else None)
        for p in SETTINGS["playlist"]:
            if Path(p).exists():
                self.add_path(p)
        self.bw = browser
        self.web_label = QLabel("Browser media: nothing playing")
        self.web_label.setWordWrap(True)
        lay.addWidget(self.web_label)
        r3 = QHBoxLayout()
        for t, a in (("⏮", "prev"), ("⏯", "toggle"), ("⏭", "next")):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, a=a: self.web_cmd(a))
            r3.addWidget(b)
        lay.addLayout(r3)
        self.web_timer = QTimer(self, interval=3000)
        self.web_timer.timeout.connect(self.web_poll)
        self.web_timer.start()
        self.hide()

    def web_poll(self):
        if self.isVisible():
            page = self.bw.media_page()
            if page:
                page.runJavaScript(MEDIA_JS, self._web_info)

    def _web_info(self, res):
        try:
            d = json.loads(res)
            self.web_label.setText((("▶ " if d["playing"] else "⏸ ") + (d["title"] or "")
                                    + (f" — {d['artist']}" if d["artist"] else "")) if d["has"]
                                   else "Browser media: nothing playing")
        except Exception:
            pass

    def web_cmd(self, a):
        page = self.bw.media_page()
        if page:
            page.runJavaScript(MEDIA_CMD_JS.replace("__A__", a))

    def add_path(self, p):
        it = QListWidgetItem(Path(p).name)
        it.setData(Qt.ItemDataRole.UserRole, p)
        self.list.addItem(it)

    def persist(self):
        SETTINGS["playlist"] = [self.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.list.count())]
        save_settings()

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Add music", str(Path.home() / "Music"),
                                                "Audio (*.mp3 *.wav *.flac *.ogg *.m4a *.aac)")
        for f in files:
            self.add_path(f)
        self.persist()

    def remove_sel(self):
        r = self.list.currentRow()
        if r >= 0:
            self.list.takeItem(r); self.persist()

    def play_row(self, r):
        if 0 <= r < self.list.count():
            self.cur_row = r
            it = self.list.item(r)
            self.player.setSource(QUrl.fromLocalFile(it.data(Qt.ItemDataRole.UserRole)))
            self.player.play()
            self.now.setText("▶ " + it.text())
            self.list.setCurrentRow(r)

    def toggle(self):
        if not self.player.source().isValid():
            self.play_row(max(0, self.list.currentRow()))
        elif self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.player.pause()
        else:
            self.player.play()

    def next(self):
        if self.list.count():
            self.play_row((self.cur_row + 1) % self.list.count())

    def prev(self):
        if self.list.count():
            self.play_row((self.cur_row - 1) % self.list.count())

    def set_vol(self, v):
        self.audio.setVolume(v / 100)
        SETTINGS["volume"] = v
        save_settings()



DOH = {"Off": "", "Quad9": "https://dns.quad9.net/dns-query",
       "Cloudflare": "https://cloudflare-dns.com/dns-query", "Mullvad": "https://dns.mullvad.net/dns-query"}
DANGEROUS_EXT = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".scr", ".jar",
                 ".com", ".lnk", ".hta", ".dll", ".reg", ".apk", ".dmg", ".pkg", ".sh", ".iso", ".scf", ".url",
                 ".chm", ".vhd", ".vhdx", ".msix", ".appx", ".jnlp", ".pif", ".cpl", ".msp", ".wsh", ".inf"}
PRESETS = {
    "Balanced": {"shield": True, "https": True, "block_3p_cookies": True, "strip_params": True,
                 "fingerprint": True, "cosmetic": True, "gpc": True, "popup_block": True, "dl_warn": True,
                 "spoof_screen": True, "spoof_tz": False, "webrtc_off": False, "clear_on_exit": False,
                 "paranoid": False, "doh": "Off"},
    "Maximum privacy": {"shield": True, "https": True, "block_3p_cookies": True, "strip_params": True,
                        "fingerprint": True, "cosmetic": True, "gpc": True, "popup_block": True,
                        "dl_warn": True, "spoof_screen": True, "spoof_tz": True, "webrtc_off": True,
                        "clear_on_exit": True, "paranoid": True, "doh": "Quad9"},
}
PRIVACY_FLAGS = [
    "--disable-background-networking", "--no-pings", "--disable-domain-reliability",
    "--disable-component-update", "--disable-client-side-phishing-detection", "--disable-sync",
    "--no-default-browser-check", "--disable-breakpad",
    "--disable-features=BrowsingTopics,PrivacySandboxAdsAPIs,InterestCohortAPI,FledgeInterestGroupAPI,"
    "AttributionReportingCrossAppWeb,Translate,OptimizationHints,MediaRouter,NetworkPrediction,"
    "NetworkTimeServiceQuerying",
]
FLOAT_ON_JS = r"""(()=>{const vs=[...document.querySelectorAll('video')].filter(v=>v.readyState>0);
if(!vs.length)return false;
vs.sort((a,b)=>b.videoWidth*b.videoHeight-a.videoWidth*a.videoHeight);const v=vs[0];
if(!v.dataset.novaOld)v.dataset.novaOld=v.getAttribute('style')||' ';
v.style.cssText='position:fixed!important;inset:0!important;width:100vw!important;height:100vh!important;z-index:2147483647!important;background:#000!important;object-fit:contain!important;';
document.documentElement.style.overflow='hidden';return true;})();"""
FLOAT_OFF_JS = r"""(()=>{const v=document.querySelector('video[data-nova-old]');
if(v){v.setAttribute('style',v.dataset.novaOld.trim());delete v.dataset.novaOld;}
document.documentElement.style.overflow='';})();"""
AUTOFILL_JS = r"""(()=>{const U=__U__,P=__P__;const inputs=[...document.querySelectorAll('input')];
const pw=inputs.find(i=>i.type==='password'&&i.offsetParent);if(!pw)return;
let user=null;for(const i of inputs){if(i===pw)break;if(['text','email','tel'].includes(i.type)&&i.offsetParent)user=i;}
const set=(el,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,v);
el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
if(user)set(user,U);set(pw,P);})();"""


def find_widevine():
    """Best effort: reuse a Widevine CDM already installed with Chrome/Edge/Brave (not bundled)."""
    found = []
    if sys.platform == "win32":
        bases = [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
                 os.environ.get("LOCALAPPDATA", "")]
        pats = ["Google/Chrome/Application/*/WidevineCdm/_platform_specific/win_x64/widevinecdm.dll",
                "Microsoft/Edge/Application/*/WidevineCdm/_platform_specific/win_x64/widevinecdm.dll",
                "BraveSoftware/Brave-Browser/Application/*/WidevineCdm/_platform_specific/win_x64/widevinecdm.dll",
                "Google/Chrome/User Data/WidevineCdm/*/_platform_specific/win_x64/widevinecdm.dll"]
    else:
        bases = ["/opt/google/chrome", "/usr/lib/chromium", "/usr/lib64/chromium"]
        pats = ["WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so", "libwidevinecdm.so"]
    for b in bases:
        if b:
            for p in pats:
                found += sorted(Path(b).glob(p))
    return found[-1] if found else None


def wipe_storage():
    """Deletes the Chromium profile (cookies, cache, site data) and Tor state on start if requested."""
    marker = DATA / "wipe_on_start"
    if not (marker.exists() or SETTINGS["clear_on_exit"]):
        return
    for loc in (QStandardPaths.StandardLocation.AppDataLocation, QStandardPaths.StandardLocation.CacheLocation):
        shutil.rmtree(Path(QStandardPaths.writableLocation(loc)) / "QtWebEngine" / PROFILE_ID, ignore_errors=True)
    shutil.rmtree(DATA_TOR, ignore_errors=True)
    marker.unlink(missing_ok=True)


def unlock_flow():
    """Master password prompt (only if the user enabled app lock)."""
    global KEY
    if not SETTINGS["app_lock"]:
        return True
    if not HAVE_CRYPTO:
        QMessageBox.critical(None, "Nova", "App lock needs the 'cryptography' package.")
        return False
    try:
        salt = (DATA / "lock.salt").read_bytes()
        chk = (DATA / "lock.check").read_bytes()
    except OSError:
        return True
    for _ in range(3):
        pw, ok = QInputDialog.getText(None, "Nova is locked", "Master password:", QLineEdit.EchoMode.Password)
        if not ok:
            return False
        k = derive_key(pw, salt)
        try:
            AESGCM(k).decrypt(chk[:12], chk[12:], None)
            KEY = k
            return True
        except Exception:
            QMessageBox.warning(None, "Nova", "Wrong password.")
    return False


class ThrottleProxy(threading.Thread):
    """Local 127.0.0.1 HTTP/CONNECT proxy that caps total bandwidth (experimental network limiter)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.port = 0
        self.ready = threading.Event()
        self.tokens = 0.0
        self.last = time.monotonic()

    async def take(self, n):
        rate = max(8, SETTINGS["net_kbs"]) * 1024
        now = time.monotonic()
        self.tokens = min(rate, self.tokens + (now - self.last) * rate)
        self.last = now
        self.tokens -= n
        if self.tokens < 0:
            await asyncio.sleep(-self.tokens / rate)

    async def pipe(self, src, dst):
        try:
            while True:
                data = await src.read(16384)
                if not data:
                    break
                await self.take(len(data))
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    async def handle(self, r, w):
        try:
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 30)
            method, target, ver = head.split(b"\r\n", 1)[0].decode("latin1").split(" ", 2)
            if method == "CONNECT":
                host, _, port = target.rpartition(":")
                ur, uw = await asyncio.open_connection(host.strip("[]"), int(port))
                w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await w.drain()
            else:
                u = urllib.parse.urlsplit(target)
                ur, uw = await asyncio.open_connection(u.hostname, u.port or 80)
                path = (u.path or "/") + ("?" + u.query if u.query else "")
                lines = [l for l in head.split(b"\r\n") if l and not l.lower().startswith((b"proxy-connection:", b"connection:"))]
                lines[0] = f"{method} {path} {ver}".encode("latin1")
                uw.write(b"\r\n".join(lines) + b"\r\nConnection: close\r\n\r\n")
                await uw.drain()
            await asyncio.gather(self.pipe(r, uw), self.pipe(ur, w))
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(asyncio.start_server(self.handle, "127.0.0.1", 0))
        self.port = server.sockets[0].getsockname()[1]
        self.ready.set()
        loop.run_forever()


class FloatWindow(QWidget):
    """Always-on-top mini window holding a tab whose video fills the page (picture-in-picture)."""

    def __init__(self, tab, browser):
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint)
        self.tab, self.browser = tab, browser
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(tab)
        tab.show()
        self.resize(480, 270)
        self.setWindowTitle("Nova — floating video (close to return to tab)")

    def closeEvent(self, e):
        self.tab.page().runJavaScript(FLOAT_OFF_JS)
        self.layout().removeWidget(self.tab)
        self.browser.tabs.addTab(self.tab, "…")
        self.browser.update_tab_text(self.tab)
        if self in self.browser._floats:
            self.browser._floats.remove(self)
        super().closeEvent(e)


class VaultDialog(QDialog):
    """Encrypted password vault (AES-256-GCM, key from your master password via scrypt)."""

    def __init__(self, browser):
        super().__init__(browser)
        self.b = browser
        self.setWindowTitle("Vault")
        self.resize(520, 420)
        self.data = load_json(VAULT_FILE, {})
        self.data.setdefault("entries", [])
        lay = QVBoxLayout(self)
        self.list = QListWidget()
        lay.addWidget(self.list)
        row = QHBoxLayout()
        for t, f in (("Add", self.add), ("Autofill", self.fill), ("Copy password", self.copy), ("Delete", self.delete)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, f=f: f())
            row.addWidget(b)
        lay.addLayout(row)
        self.refresh()

    def save(self):
        save_json(VAULT_FILE, self.data)

    def refresh(self):
        self.list.clear()
        for e in self.data["entries"]:
            self.list.addItem(f"{e['site']} — {e['user']}")

    def sel(self):
        r = self.list.currentRow()
        return self.data["entries"][r] if r >= 0 else None

    def add(self):
        site, ok = QInputDialog.getText(self, "Vault", "Site (e.g. example.com):")
        if not ok or not site.strip():
            return
        site = site.strip().lower()
        if "//" in site:
            site = urllib.parse.urlsplit(site).hostname or site
        user, ok = QInputDialog.getText(self, "Vault", "Username / email:")
        if not ok:
            return
        pw, ok = QInputDialog.getText(self, "Vault", "Password (leave empty to generate a strong one):",
                                      QLineEdit.EchoMode.Password)
        if not ok:
            return
        if not pw:
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
            pw = "".join(secrets.choice(alphabet) for _ in range(22))
            QApplication.clipboard().setText(pw)
            QTimer.singleShot(20000, QApplication.clipboard().clear)
            QMessageBox.information(self, "Vault", "Generated a 22-character password and copied it "
                                    "(clipboard clears in 20 s).")
        self.data["entries"].append({"site": site, "user": user, "pw": pw})
        self.save(); self.refresh()

    def delete(self):
        r = self.list.currentRow()
        if r >= 0:
            del self.data["entries"][r]
            self.save(); self.refresh()

    def copy(self):
        e = self.sel()
        if e:
            QApplication.clipboard().setText(e["pw"])
            QTimer.singleShot(20000, QApplication.clipboard().clear)

    def fill(self):
        e = self.sel()
        if not e:
            return
        if self.b.cur().url().scheme() != "https":
            QMessageBox.warning(self, "Vault", "Autofill only works on secure (HTTPS) pages.")
            return
        host = self.b.cur().url().host().lower()
        if not (host == e["site"] or host.endswith("." + e["site"])):
            QMessageBox.warning(self, "Vault", f"This page is {host or 'blank'}, not {e['site']}.\n"
                                "Refusing to autofill (possible phishing).")
            return
        self.b.cur().page().runJavaScript(
            AUTOFILL_JS.replace("__U__", json.dumps(e["user"])).replace("__P__", json.dumps(e["pw"])))


class AskThread(QThread):
    done = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, key, model, messages, system):
        super().__init__()
        self.key, self.model, self.messages, self.system = key, model, messages, system

    def run(self):
        try:
            body = json.dumps({"model": self.model, "max_tokens": 1024, "system": self.system,
                               "messages": self.messages}).encode()
            req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
                "x-api-key": self.key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.load(r)
            self.done.emit("".join(b.get("text", "") for b in data.get("content", [])))
        except urllib.error.HTTPError as e:
            self.failed.emit(f"HTTP {e.code}: {e.read().decode(errors='ignore')[:300]}")
        except Exception as e:
            self.failed.emit(str(e))


class AssistantDock(QDockWidget):
    """Opt-in AI sidebar (like Brave's Leo) using YOUR Anthropic API key, stored in the encrypted vault."""

    def __init__(self, browser):
        super().__init__("Ask Claude", browser)
        self.b, self.history = browser, []
        w = QWidget(); lay = QVBoxLayout(w)
        self.log = QTextBrowser()
        lay.addWidget(self.log)
        self.inp = QLineEdit(placeholderText="Ask about this page…")
        self.inp.returnPressed.connect(lambda: self.send(False))
        lay.addWidget(self.inp)
        row = QHBoxLayout()
        b1 = QPushButton("Send"); b1.clicked.connect(lambda _=False: self.send(False))
        b2 = QPushButton("Summarize page"); b2.clicked.connect(lambda _=False: self.send(True))
        row.addWidget(b1); row.addWidget(b2)
        lay.addLayout(row)
        warn = QLabel("Opt-in. Page text is sent to Anthropic with your own API key. "
                      "Disabled in private and Tor windows.")
        warn.setWordWrap(True)
        lay.addWidget(warn)
        self.setWidget(w)

    def api_key(self):
        if KEY is None:
            QMessageBox.information(self, "Ask Claude", "Set a master password first (☰ → Security & privacy).")
            return None
        v = load_json(VAULT_FILE, {})
        k = v.get("api_key", "")
        if not k:
            k, ok = QInputDialog.getText(self, "Anthropic API key", "Paste your API key (stored encrypted):",
                                         QLineEdit.EchoMode.Password)
            if not ok or not k.strip():
                return None
            k = k.strip()
            v["api_key"] = k
            save_json(VAULT_FILE, v)
        return k

    def send(self, summarize, preset=None):
        if not SETTINGS["ai_enabled"]:
            QMessageBox.information(self, "Ask Claude", "Enable the assistant in ⚙ → Ask Claude first.")
            return
        if self.b.tor or self.b.ephemeral:
            QMessageBox.information(self, "Ask Claude", "Disabled in private / Tor / paranoid mode.")
            return
        q = preset or ("Summarize this page in a few short bullet points." if summarize else self.inp.text().strip())
        if not q:
            return
        key = self.api_key()
        if not key:
            return
        self.inp.clear()
        self.log.append(f"<b>You:</b> {htmllib.escape(q)}")
        self.b.cur().page().toPlainText(lambda txt: self.go(key, q, txt))

    def go(self, key, q, txt):
        t = self.b.cur()
        self.history.append({"role": "user", "content": f"[Page: {t.title()} — {t.url().toString()}]\n{txt[:30000]}\n\n{q}"})
        th = AskThread(key, SETTINGS["ai_model"], self.history[-5:],
                       "You are a concise assistant inside a web browser. Use the page text when relevant.")
        th.done.connect(self.on_done)
        th.failed.connect(self.on_fail)
        self.b.run_thread(th)

    def on_done(self, text):
        self.history.append({"role": "assistant", "content": text})
        self.log.append("<b>Claude:</b> " + htmllib.escape(text).replace("\n", "<br>"))

    def on_fail(self, err):
        if self.history and self.history[-1]["role"] == "user":
            self.history.pop()
        self.log.append("<i>" + htmllib.escape(err) + "</i>")



APP_CATALOG = [  # short, name, url, mode, colour
    ("WA", "WhatsApp", "https://web.whatsapp.com", "panel", "#25D366"),
    ("TG", "Telegram", "https://web.telegram.org", "panel", "#229ED9"),
    ("DC", "Discord", "https://discord.com/app", "panel", "#5865F2"),
    ("MS", "Messenger", "https://www.messenger.com", "panel", "#0084FF"),
    ("SP", "Spotify", "https://open.spotify.com", "panel", "#1DB954"),
    ("YT", "YouTube", "https://www.youtube.com", "tab", "#FF0033"),
    ("TW", "Twitch", "https://www.twitch.tv", "tab", "#9146FF"),
    ("X", "X / Twitter", "https://x.com", "tab", "#15151b"),
    ("MT", "Jitsi Meet (calls)", "https://meet.jit.si", "tab", "#1D76BA"),
    ("IG", "Instagram", "https://www.instagram.com", "panel", "#E1306C"),
    ("FB", "Facebook", "https://www.facebook.com", "tab", "#1877F2"),
    ("TT", "TikTok", "https://www.tiktok.com", "tab", "#111111"),
    ("RD", "Reddit", "https://www.reddit.com", "tab", "#FF4500"),
    ("GM", "Gmail", "https://mail.google.com", "panel", "#EA4335"),
    ("IN", "LinkedIn", "https://www.linkedin.com", "tab", "#0A66C2"),
    ("SL", "Slack", "https://app.slack.com", "panel", "#4A154B"),
    ("YM", "YouTube Music", "https://music.youtube.com", "panel", "#FF0000"),
    ("SC", "SoundCloud", "https://soundcloud.com", "panel", "#FF5500"),
    ("NF", "Netflix", "https://www.netflix.com", "tab", "#E50914"),
    ("GH", "GitHub", "https://github.com", "tab", "#24292f"),
    ("NO", "Notion", "https://www.notion.so", "tab", "#2b2b2b"),
    ("MP", "Maps", "https://www.google.com/maps", "tab", "#34A853"),
]
ISLAND_COLORS = ["#fa1e4e", "#00d9ff", "#7cff00", "#ffb800", "#a855f7", "#ff7a00"]
ADDR_FIELDS = [("name", "Full name"), ("email", "Email"), ("phone", "Phone"), ("street", "Street address"),
               ("city", "City"), ("state", "State / region"), ("zip", "Postal code"), ("country", "Country")]
ALLOWED_SCHEMES = {"http", "https", "about", "data", "blob", "qrc", "view-source", "devtools", "file",
                   "chrome-error", "ipfs", "ipns"}

COOKIE_JS = r"""(()=>{const OFF=__OFF__,h=location.hostname;if(OFF.some(x=>h===x||h.endsWith('.'+x)))return;
const sel=['#onetrust-reject-all-handler','#CybotCookiebotDialogBodyButtonDecline','#didomi-notice-disagree-button',
'button[data-testid="uc-deny-all-button"]','.qc-cmp2-summary-buttons button[mode="secondary"]','.cc-deny','.cmplz-deny',
'button.cky-btn-reject','#wt-cli-reject-btn','.fc-cta-do-not-consent','#cookie-reject','.js-cookie-reject'];
const words=/^(reject all|reject|decline|deny|refuse|only necessary|necessary only|essential only|use necessary cookies only|continue without accepting|i do not accept|no thanks)$/i;
const ctx=/cookie|consent|gdpr|cmp|privacy/i;
const tryClick=()=>{for(const s of sel){const b=document.querySelector(s);if(b&&b.offsetParent!==null){b.click();return true;}}
for(const el of document.querySelectorAll('div,section,aside,form,dialog')){const id=String(el.id||'')+' '+String(typeof el.className==='string'?el.className:'');
if(ctx.test(id)&&el.offsetParent!==null){for(const b of el.querySelectorAll('button,a,[role=button]')){if(words.test((b.innerText||'').trim())){b.click();return true;}}}}return false;};
let n=0;const iv=setInterval(()=>{if(tryClick()||++n>25)clearInterval(iv);},600);})();"""

FILL_JS = r"""(()=>{const V=__V__;
const keys=[['cc-number','cc_number',/card.?num|cc.?num|number/i],['cc-name','cc_name',/card.?holder|name.?on.?card|cc.?name/i],
['cc-exp-month','cc_month',/exp.*month|month/i],['cc-exp-year','cc_year',/exp.*year|year/i],['cc-exp','cc_exp',/exp(iry|iration)?|mm.?yy/i],
['given-name','first',/first.?name|fname|given/i],['family-name','last',/last.?name|lname|surname|family/i],['name','name',/^name$|full.?name/i],
['email','email',/e-?mail/i],['tel','phone',/phone|mobile|tel/i],['address-line1','street',/address|street/i],['address-level2','city',/city|town/i],
['address-level1','state',/state|region|province/i],['postal-code','zip',/zip|postal|post.?code/i],['country-name','country',/country/i],['country','country',/country/i]];
const set=(el,v)=>{const proto=el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;
Object.getOwnPropertyDescriptor(proto,'value').set.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
let n=0;for(const el of document.querySelectorAll('input,select')){
if(!el.offsetParent||['hidden','password','submit','checkbox','radio','button'].includes(el.type))continue;
const ac=(el.getAttribute('autocomplete')||'').toLowerCase();const hint=[el.name,el.id,el.placeholder,el.getAttribute('aria-label')].join(' ');
for(const [a,k,rx] of keys){if(V[k]===undefined||V[k]==='')continue;
if(ac.split(' ').includes(a)||((!ac||ac==='on'||ac==='off')&&rx.test(hint))){set(el,V[k]);n++;break;}}}
return n;})()"""

MEDIA_JS = r"""(()=>{const m=navigator.mediaSession&&navigator.mediaSession.metadata;
const v=[...document.querySelectorAll('video,audio')].find(x=>!x.paused)||document.querySelector('video,audio');
return JSON.stringify({title:m&&m.title?m.title:document.title,artist:m?m.artist:'',playing:!!(v&&!v.paused),has:!!v});})()"""

MEDIA_CMD_JS = r"""((a)=>{const q=s=>document.querySelector(s);
const map={next:['[data-testid="control-button-skip-forward"]','.ytp-next-button','.next-button','[aria-label="Next"]','[aria-label="Next song"]'],
prev:['[data-testid="control-button-skip-back"]','.previous-button','[aria-label="Previous"]','[aria-label="Previous song"]']};
if(a==='toggle'){const v=[...document.querySelectorAll('video,audio')].find(x=>!x.paused)||document.querySelector('video,audio');if(v){v.paused?v.play():v.pause();}return;}
for(const s of map[a]||[]){const b=q(s);if(b){b.click();return;}}})('__A__')"""

EXT_JS = r"""(function(){const M=__M__,X=__X__,u=location.href;
if(!M.some(p=>new RegExp(p).test(u))||X.some(p=>new RegExp(p).test(u)))return;
const key='nova_ext:__ID__';const all=()=>{try{return JSON.parse(localStorage.getItem(key)||'{}')}catch(e){return {}}};
const area={get(k,cb){const a=all();let o={};if(k==null)o=a;else if(typeof k==='string')o[k]=a[k];else if(Array.isArray(k))k.forEach(x=>o[x]=a[x]);else for(const x in k)o[x]=x in a?a[x]:k[x];
if(cb)cb(o);return Promise.resolve(o);},set(o,cb){const a=all();Object.assign(a,o);localStorage.setItem(key,JSON.stringify(a));if(cb)cb();return Promise.resolve();},
remove(k,cb){const a=all();[].concat(k).forEach(x=>delete a[x]);localStorage.setItem(key,JSON.stringify(a));if(cb)cb();return Promise.resolve();}};
const chrome={runtime:{id:'__ID__',getURL:p=>'',getManifest:()=>__MANIFEST__,sendMessage:()=>Promise.resolve(),onMessage:{addListener(){}},connect:()=>({postMessage(){},onMessage:{addListener(){}}})},
storage:{local:area,sync:area,onChanged:{addListener(){}}},i18n:{getMessage:k=>k,getUILanguage:()=>navigator.language},extension:{getURL:p=>''}};
const css=__CSS__;if(css){const st=document.createElement('style');st.textContent=css;(document.head||document.documentElement).appendChild(st);}
(function(chrome,browser){__CODE__
})(chrome,chrome);})();"""

UNSAFE_HTML = """<html><body style="margin:0;background:#2a0a10;color:#fff;font-family:Segoe UI,sans-serif;text-align:center;padding-top:16vh">
<h1 style="color:#ff5470">⚠ Dangerous page blocked</h1><p style="font-size:18px;color:#ffc4cf">Google Safe Browsing reports this page as <b>__KIND__</b>.</p>
<p style="color:#bba">__URL__</p><p><button onclick="history.back()" style="color:#fff;background:#fa1e4e;padding:12px 24px;border:0;border-radius:10px;font-size:16px;cursor:pointer">Back to safety</button></p></body></html>"""

class _NoDowngrade(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("refusing a redirect to a non-HTTPS address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


SAFE_OPENER = urllib.request.build_opener(_NoDowngrade)


class Holder(QWidget):
    """Hosts one tab. With letterboxing on, the page area is rounded to 200x100 steps (like Tor Browser)."""

    def __init__(self, child, letterbox):
        super().__init__()
        self.child, self.lb = child, letterbox
        child.setParent(self)
        child.show()

    def resizeEvent(self, e):
        w, h = self.width(), self.height()
        cw, ch = (max(200, w // 200 * 200), max(100, h // 100 * 100)) if self.lb else (w, h)
        self.child.setGeometry((w - cw) // 2, (h - ch) // 2, cw, ch)


class QuickPicker(QDialog):
    """Type-to-filter list used for tab search and the command palette."""

    def __init__(self, parent, title, entries, placeholder="Type to filter…"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(580, 440)
        self.entries, self.shown = entries, []
        lay = QVBoxLayout(self)
        self.edit = QLineEdit(placeholderText=placeholder)
        self.list = QListWidget()
        lay.addWidget(self.edit)
        lay.addWidget(self.list)
        self.edit.textChanged.connect(self.refresh)
        self.edit.returnPressed.connect(self.run)
        self.edit.installEventFilter(self)
        self.list.itemActivated.connect(lambda _i: self.run())
        self.refresh("")

    def eventFilter(self, obj, ev):
        if obj is self.edit and ev.type() == QEvent.Type.KeyPress and ev.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
            step = 1 if ev.key() == Qt.Key.Key_Down else -1
            self.list.setCurrentRow(max(0, min(self.list.count() - 1, self.list.currentRow() + step)))
            return True
        return super().eventFilter(obj, ev)

    def refresh(self, q):
        words = q.lower().split()
        self.shown = [e for e in self.entries if all(w in e[0].lower() for w in words)]
        self.list.clear()
        self.list.addItems([e[0] for e in self.shown])
        if self.shown:
            self.list.setCurrentRow(0)

    def run(self):
        r = self.list.currentRow()
        if 0 <= r < len(self.shown):
            fn = self.shown[r][1]
            self.accept()
            fn()


class EasyFilesDialog(QDialog):
    """Opera-style 'Easy Files': pick from recent downloads/screenshots when a site asks for a file."""

    def __init__(self, parent, files, multiple):
        super().__init__(parent)
        self.setWindowTitle("Choose a file — recent files")
        self.resize(580, 420)
        self.files, self.multiple, self.result_files = files, multiple, []
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Recent downloads and screenshots:"))
        self.list = QListWidget()
        self.list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection if multiple
                                   else QListWidget.SelectionMode.SingleSelection)
        for f in files:
            self.list.addItem(f"{Path(f).name}    —    {Path(f).parent}")
        lay.addWidget(self.list)
        row = QHBoxLayout()
        for t, fn in (("Use selected", self.use), ("Browse…", self.browse), ("Cancel", self.reject)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            row.addWidget(b)
        lay.addLayout(row)

    def use(self):
        self.result_files = [self.files[self.list.row(i)] for i in self.list.selectedItems()]
        self.accept()

    def browse(self):
        if self.multiple:
            fs, _ = QFileDialog.getOpenFileNames(self, "Choose files")
        else:
            f, _ = QFileDialog.getOpenFileName(self, "Choose a file")
            fs = [f] if f else []
        if fs:
            self.result_files = fs
            self.accept()


class ListTab(QWidget):
    def __init__(self, items_fn, label_fn, open_fn=None, delete_fn=None, extra=()):
        super().__init__()
        self.items_fn, self.label_fn, self.open_fn, self.delete_fn, self.shown = items_fn, label_fn, open_fn, delete_fn, []
        lay = QVBoxLayout(self)
        self.search = QLineEdit(placeholderText="Search…")
        self.list = QListWidget()
        lay.addWidget(self.search)
        lay.addWidget(self.list)
        row = QHBoxLayout()
        btns = ([("Open", self.do_open)] if open_fn else []) + ([("Delete", self.do_delete)] if delete_fn else [])
        btns += [(t, (lambda f=f: self.do_extra(f))) for t, f in extra]
        for t, f in btns:
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, f=f: f())
            row.addWidget(b)
        lay.addLayout(row)
        self.search.textChanged.connect(self.refresh)
        if open_fn:
            self.list.itemDoubleClicked.connect(lambda _i: self.do_open())
        self.refresh()

    def refresh(self):
        q = self.search.text().lower().strip()
        self.shown = [it for it in self.items_fn() if q in self.label_fn(it).lower()][:600]
        self.list.clear()
        self.list.addItems([self.label_fn(it) for it in self.shown])

    def cur(self):
        r = self.list.currentRow()
        return self.shown[r] if 0 <= r < len(self.shown) else None

    def do_open(self):
        it = self.cur()
        if it is not None:
            self.open_fn(it)

    def do_delete(self):
        it = self.cur()
        if it is not None:
            self.delete_fn(it)
            self.refresh()

    def do_extra(self, f):
        f(self.cur())
        self.refresh()


class LibraryDialog(QDialog):
    """Bookmarks, history, pinboards, Flow, downloads and site permissions in one manager."""

    def __init__(self, browser, index=0):
        super().__init__(browser)
        b = self.b = browser
        self.setWindowTitle("Library")
        self.resize(820, 580)
        lay = QVBoxLayout(self)
        tabs = QTabWidget()
        lay.addWidget(tabs)
        when = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t or 0))
        tabs.addTab(ListTab(lambda: b.bookmarks[::-1],
                            lambda x: f"{x.get('title') or x['url']}  —  {x['url']}",
                            lambda x: b.new_tab(x["url"]), self.del_bm), "Bookmarks")
        tabs.addTab(ListTab(lambda: b.history[::-1],
                            lambda x: f"{x.get('title') or ''}  {x['url']}   ({when(x.get('t'))})",
                            lambda x: b.new_tab(x["url"]), self.del_hist,
                            extra=[("Clear all history", self.clear_hist)]), "History")
        tabs.addTab(ListTab(self.pins, lambda x: f"[{x[0]}]  {x[1].get('title') or x[1]['url']}",
                            lambda x: b.new_tab(x[1]["url"]), self.del_pin,
                            extra=[("Pin current page…", lambda _x: b.pin_page())]), "Pinboards")
        tabs.addTab(ListTab(lambda: load_json(FLOW_FILE, [])[::-1],
                            lambda x: f"{x.get('kind', 'note')}:  {x['text'][:110]}",
                            lambda x: b.flow_open(x), self.del_flow,
                            extra=[("Add note…", lambda _x: b.flow_add()),
                                   ("Copy", lambda x: QApplication.clipboard().setText(x["text"]) if x else None)]),
                    "Flow")
        tabs.addTab(ListTab(lambda: load_json(DOWNLOADS_LOG, [])[::-1], lambda p: p,
                            lambda p: open_folder(Path(p).parent), self.del_dl), "Downloads")
        tabs.addTab(ListTab(self.perms, lambda x: f"{x[0]}   ·   {x[1]}   ·   {'allowed' if x[2] else 'blocked'}",
                            None, self.del_perm), "Site permissions")
        tabs.setCurrentIndex(index)

    def del_bm(self, x):
        self.b.bookmarks = [y for y in self.b.bookmarks if y["url"] != x["url"]]
        save_json(BOOKMARKS_FILE, self.b.bookmarks)

    def del_hist(self, x):
        self.b.history = [y for y in self.b.history if not (y["url"] == x["url"] and y.get("t") == x.get("t"))]
        save_json(HISTORY_FILE, self.b.history)

    def clear_hist(self, _x):
        self.b.history.clear()
        save_json(HISTORY_FILE, [])

    def pins(self):
        return [(board, e) for board, es in load_json(PIN_FILE, {}).items() for e in es]

    def del_pin(self, x):
        p = load_json(PIN_FILE, {})
        p[x[0]] = [e for e in p.get(x[0], []) if e != x[1]]
        save_json(PIN_FILE, {k: v for k, v in p.items() if v})

    def del_flow(self, x):
        save_json(FLOW_FILE, [y for y in load_json(FLOW_FILE, []) if y != x])

    def del_dl(self, p):
        save_json(DOWNLOADS_LOG, [q for q in load_json(DOWNLOADS_LOG, []) if q != p])

    def perms(self):
        return [(h, k, v) for h, d in SETTINGS["site_perms"].items() for k, v in d.items()]

    def del_perm(self, x):
        SETTINGS["site_perms"].get(x[0], {}).pop(x[1], None)
        if not SETTINGS["site_perms"].get(x[0]):
            SETTINGS["site_perms"].pop(x[0], None)
        save_settings()


def ext_list():
    out = []
    for d in (sorted(EXT_DIR.iterdir()) if EXT_DIR.exists() else []):
        m = load_json(d / "manifest.json", None)
        if d.is_dir() and isinstance(m, dict):
            out.append((d, m))
    return out


def read_ext_file(d, rel):
    p = (d / rel).resolve()
    if not p.is_relative_to(d.resolve()) or not p.is_file() or p.stat().st_size > 5_000_000:
        return ""
    return p.read_text(encoding="utf-8", errors="ignore")


def match_rx(p):
    return ".*" if p == "<all_urls>" else "^" + re.escape(p).replace(r"\*", ".*") + "$"


def load_extension_scripts():
    """Chrome-format extensions: content scripts + CSS only (no background pages, popups or toolbar buttons)."""
    out, P = [], QWebEngineScript.InjectionPoint
    for d, m in ext_list():
        if d.name in SETTINGS["ext_disabled"]:
            continue
        for i, cs in enumerate(m.get("content_scripts", [])):
            if not cs.get("matches"):
                continue
            code = "\n;".join(read_ext_file(d, r) for r in cs.get("js", []))
            css = "".join(read_ext_file(d, r) for r in cs.get("css", []))
            js = (EXT_JS.replace("__M__", json.dumps([match_rx(p) for p in cs["matches"]]))
                  .replace("__X__", json.dumps([match_rx(p) for p in cs.get("exclude_matches", [])]))
                  .replace("__ID__", re.sub(r"\W", "_", d.name)).replace("__CSS__", json.dumps(css))
                  .replace("__MANIFEST__", json.dumps({"name": m.get("name", ""), "version": m.get("version", "")}))
                  .replace("__CODE__", code))
            run = cs.get("run_at", "document_idle")
            point = (P.DocumentCreation if run == "document_start"
                     else P.DocumentReady if run == "document_end" else P.Deferred)
            out.append((f"{d.name}:{i}", js, point, bool(cs.get("all_frames", False))))
    return out


class ExtensionsDialog(QDialog):
    def __init__(self, browser):
        super().__init__(browser)
        self.b = browser
        self.setWindowTitle("Extensions")
        self.resize(560, 440)
        lay = QVBoxLayout(self)
        n = QLabel("Nova runs the content scripts and styles of Chrome-format extensions. Extensions that need a "
                   "background page, popup or toolbar button won't work. Only install extensions you trust.")
        n.setWordWrap(True)
        lay.addWidget(n)
        self.list = QListWidget()
        lay.addWidget(self.list)
        self.list.itemChanged.connect(self.toggled)
        row = QHBoxLayout()
        for t, f in (("Install from folder…", self.install_folder), ("Install .zip / .crx…", self.install_pkg),
                     ("Remove", self.remove)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, f=f: f())
            row.addWidget(b)
        lay.addLayout(row)
        self.refresh()

    def refresh(self):
        self.list.blockSignals(True)
        self.list.clear()
        for d, m in ext_list():
            it = QListWidgetItem(f"{m.get('name', d.name)}  {m.get('version', '')}")
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Unchecked if d.name in SETTINGS["ext_disabled"] else Qt.CheckState.Checked)
            it.setData(Qt.ItemDataRole.UserRole, d.name)
            self.list.addItem(it)
        self.list.blockSignals(False)

    def toggled(self, it):
        dis = set(SETTINGS["ext_disabled"])
        name = it.data(Qt.ItemDataRole.UserRole)
        (dis.discard if it.checkState() == Qt.CheckState.Checked else dis.add)(name)
        SETTINGS["ext_disabled"] = sorted(dis)
        save_settings()
        self.b.apply_scripts()

    def _install(self, src):
        m = load_json(Path(src) / "manifest.json", None)
        if not isinstance(m, dict):
            QMessageBox.warning(self, "Extensions", "No manifest.json found in that folder.")
            return
        dest = EXT_DIR / re.sub(r"[^A-Za-z0-9_.-]", "_", str(m.get("name", Path(src).name)))[:40]
        shutil.copytree(src, dest, dirs_exist_ok=True)
        self.b.apply_scripts()
        self.refresh()
        if not m.get("content_scripts"):
            QMessageBox.information(self, "Extensions", "Installed, but this extension has no content scripts, "
                                    "so it can't do anything in Nova.")

    def install_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Extension folder (contains manifest.json)")
        if d:
            self._install(d)

    def install_pkg(self):
        f, _ = QFileDialog.getOpenFileName(self, "Extension package", "", "Extension (*.zip *.crx)")
        if not f:
            return
        raw = Path(f).read_bytes()
        if raw[:4] == b"Cr24":
            ver = struct.unpack("<I", raw[4:8])[0]
            start = 12 + struct.unpack("<I", raw[8:12])[0] if ver == 3 else 16 + sum(struct.unpack("<II", raw[8:16]))
            raw = raw[start:]
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            if sum(i.file_size for i in zf.infolist()) > 100 * 1024 * 1024:
                raise ValueError("package is too large")
            tmp = Path(tempfile.mkdtemp())
            zf.extractall(tmp)
        except Exception as e:
            QMessageBox.warning(self, "Extensions", f"Couldn't read that package: {e}")
            return
        self._install(tmp)
        shutil.rmtree(tmp, ignore_errors=True)

    def remove(self):
        it = self.list.currentItem()
        if it and QMessageBox.question(self, "Extensions", "Remove this extension?") == QMessageBox.StandardButton.Yes:
            shutil.rmtree(EXT_DIR / it.data(Qt.ItemDataRole.UserRole), ignore_errors=True)
            self.b.apply_scripts()
            self.refresh()


class SidebarAppsDialog(QDialog):
    def __init__(self, browser):
        super().__init__(browser)
        self.b = browser
        self.setWindowTitle("Sidebar apps")
        self.resize(420, 520)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Choose which apps appear in the sidebar:"))
        self.list = QListWidget()
        lay.addWidget(self.list)
        b = QPushButton("Add a custom app…")
        b.clicked.connect(lambda _=False: self.add_custom())
        lay.addWidget(b)
        self.list.itemChanged.connect(self.changed)
        self.refresh()

    def refresh(self):
        self.list.blockSignals(True)
        self.list.clear()
        chosen = SETTINGS["sidebar_apps"]
        for s, n, u, m, c in APP_CATALOG:
            it = QListWidgetItem(n)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if s in chosen else Qt.CheckState.Unchecked)
            it.setData(Qt.ItemDataRole.UserRole, s)
            self.list.addItem(it)
        for a in SETTINGS["custom_apps"]:
            it = QListWidgetItem(a["name"] + "  (custom — uncheck to remove)")
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked)
            it.setData(Qt.ItemDataRole.UserRole, "custom:" + a["short"])
            self.list.addItem(it)
        self.list.blockSignals(False)

    def changed(self, _it):
        chosen, custom = [], []
        for i in range(self.list.count()):
            it = self.list.item(i)
            key = it.data(Qt.ItemDataRole.UserRole)
            if it.checkState() == Qt.CheckState.Checked:
                if key.startswith("custom:"):
                    custom += [a for a in SETTINGS["custom_apps"] if "custom:" + a["short"] == key]
                else:
                    chosen.append(key)
        SETTINGS["sidebar_apps"], SETTINGS["custom_apps"] = chosen, custom
        save_settings()
        self.b.fill_sidebar()

    def add_custom(self):
        name, ok = QInputDialog.getText(self, "Custom app", "Name:")
        if not ok or not name.strip():
            return
        url, ok = QInputDialog.getText(self, "Custom app", "Address (https://…):")
        if not ok or not url.strip().lower().startswith(("http://", "https://")):
            QMessageBox.warning(self, "Custom app", "Enter a full http(s) address.")
            return
        short = re.sub(r"[^A-Za-z0-9]", "", name)[:2].upper() or "?"
        SETTINGS["custom_apps"].append({"short": short, "name": name.strip(), "url": url.strip()})
        save_settings()
        self.refresh()
        self.b.fill_sidebar()


class AutofillDialog(QDialog):
    """Address and card autofill, stored encrypted in the vault (needs the master password). CVV is never stored."""

    def __init__(self, browser):
        super().__init__(browser)
        self.b = browser
        self.setWindowTitle("Autofill — addresses & cards")
        self.resize(520, 600)
        self.data = load_json(VAULT_FILE, {})
        self.af = self.data.setdefault("autofill", {})
        self.af.setdefault("address", {})
        self.af.setdefault("cards", [])
        lay = QVBoxLayout(self)
        g = QGroupBox("Address")
        gl = QVBoxLayout(g)
        self.fields = {}
        for k, label in ADDR_FIELDS:
            e = QLineEdit(self.af["address"].get(k, ""))
            e.setPlaceholderText(label)
            self.fields[k] = e
            gl.addWidget(e)
        row = QHBoxLayout()
        for t, f in (("Save address", self.save_addr), ("Fill into this page", self.fill_addr)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, f=f: f())
            row.addWidget(b)
        gl.addLayout(row)
        lay.addWidget(g)
        g2 = QGroupBox("Cards")
        cl = QVBoxLayout(g2)
        self.cards = QListWidget()
        cl.addWidget(self.cards)
        row = QHBoxLayout()
        for t, f in (("Add card…", self.add_card), ("Delete", self.del_card), ("Fill selected card", self.fill_card)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, f=f: f())
            row.addWidget(b)
        cl.addLayout(row)
        lay.addWidget(g2)
        self.refresh()

    def save(self):
        save_json(VAULT_FILE, self.data)

    def refresh(self):
        self.cards.clear()
        for c in self.af["cards"]:
            self.cards.addItem(f"{c['label']} — {c['name']} — •••• {c['number'][-4:]} — {c['exp']}")

    def save_addr(self):
        self.af["address"] = {k: e.text().strip() for k, e in self.fields.items()}
        self.save()

    def fill_addr(self):
        a = {k: e.text().strip() for k, e in self.fields.items()}
        parts = a.get("name", "").split(" ", 1)
        a["first"], a["last"] = parts[0], (parts[1] if len(parts) > 1 else "")
        self.accept()
        self.b.fill_form(a)

    def add_card(self):
        label, ok = QInputDialog.getText(self, "Card", "Label (e.g. Visa personal):")
        if not ok:
            return
        name, ok = QInputDialog.getText(self, "Card", "Name on card:")
        if not ok:
            return
        num, ok = QInputDialog.getText(self, "Card", "Card number:", QLineEdit.EchoMode.Password)
        num = re.sub(r"\D", "", num)
        if not ok or not 12 <= len(num) <= 19:
            QMessageBox.warning(self, "Card", "That doesn't look like a card number.")
            return
        exp, ok = QInputDialog.getText(self, "Card", "Expiry (MM/YY):")
        if ok and re.fullmatch(r"\d{2}/\d{2}", exp.strip()):
            self.af["cards"].append({"label": label.strip() or "Card", "name": name.strip(), "number": num, "exp": exp.strip()})
            self.save()
            self.refresh()

    def del_card(self):
        r = self.cards.currentRow()
        if r >= 0:
            del self.af["cards"][r]
            self.save()
            self.refresh()

    def fill_card(self):
        r = self.cards.currentRow()
        if r < 0:
            return
        c = self.af["cards"][r]
        host = self.b.cur().url().host()
        if QMessageBox.question(self, "Fill card", f"Fill {c['label']} (•••• {c['number'][-4:]}) into {host}?"
                                ) != QMessageBox.StandardButton.Yes:
            return
        mm, yy = c["exp"].split("/")
        self.accept()
        self.b.fill_form({"cc_name": c["name"], "cc_number": c["number"], "cc_month": mm, "cc_year": "20" + yy,
                          "cc_exp": c["exp"]})


class GsbThread(QThread):
    """Optional Google Safe Browsing lookup (your own API key). Sends the page address to Google."""
    flagged = pyqtSignal(str, str)

    def __init__(self, key, url):
        super().__init__()
        self.key, self.url = key, url

    def run(self):
        try:
            body = json.dumps({"client": {"clientId": "nova-browser", "clientVersion": VERSION},
                               "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                                              "POTENTIALLY_HARMFUL_APPLICATION"],
                                              "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                              "threatEntries": [{"url": self.url}]}}).encode()
            req = urllib.request.Request("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + quote(self.key),
                                         data=body, headers={"Content-Type": "application/json"})
            with SAFE_OPENER.open(req, timeout=10) as r:
                m = json.load(r).get("matches")
            if m:
                self.flagged.emit(self.url, m[0].get("threatType", "UNSAFE").replace("_", " ").lower())
        except Exception:
            pass


class ChromaLink:
    """Razer Chroma lighting through Razer Synapse's local REST SDK. Colours show Nova's state."""
    BASE = "http://localhost:54235/razer/chromasdk"

    def __init__(self):
        self.uri, self.color, self.stop_evt = None, None, threading.Event()

    def _req(self, method, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read() or b"{}")

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            self.uri = self._req("POST", self.BASE, {
                "title": "Nova Browser", "description": "Browser status lighting",
                "author": {"name": "Nova", "contact": "https://example.com"},
                "device_supported": ["keyboard", "mouse", "headset", "mousepad", "keypad", "chromalink"],
                "category": "application"})["uri"]
        except Exception:
            return
        while not self.stop_evt.is_set():
            try:
                self._req("PUT", self.uri + "/heartbeat")
                if self.color is not None:
                    for dev in ("keyboard", "mouse", "headset", "mousepad", "keypad", "chromalink"):
                        self._req("PUT", f"{self.uri}/{dev}", {"effect": "CHROMA_STATIC", "param": {"color": self.color}})
                    self.color = None
            except Exception:
                pass
            self.stop_evt.wait(5)

    def set_hex(self, h):
        self.color = int(h[1:3], 16) | int(h[3:5], 16) << 8 | int(h[5:7], 16) << 16

    def stop(self):
        self.stop_evt.set()
        try:
            if self.uri:
                self._req("DELETE", self.uri)
        except Exception:
            pass


class TabArea(QWidget):
    """Chrome-style layout: tab strip on top, then the toolbar, then the page. Mimics the QTabWidget API."""
    tabCloseRequested = pyqtSignal(int)
    currentChanged = pyqtSignal(int)

    def __init__(self, letterbox=False):
        super().__init__()
        self._w = []
        self._hold = {}
        self.letterbox = letterbox
        self.bar = QTabBar()
        self.bar.setDocumentMode(True)
        self.bar.setExpanding(False)
        self.bar.setMovable(True)
        self.bar.setTabsClosable(True)
        self.bar.setDrawBase(False)
        self.bar.setElideMode(Qt.TextElideMode.ElideRight)
        self.bar.setUsesScrollButtons(True)
        self.plus = QToolButton()
        self.plus.setObjectName("newtab")
        self.plus.setIcon(svg_icon("plus"))
        self.plus.setToolTip("New tab (Ctrl+T)")
        self.stack = QStackedWidget()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        head = QWidget()
        head.setObjectName("tabstrip")
        hl = QHBoxLayout(head)
        hl.setContentsMargins(10, 8, 10, 0)
        hl.setSpacing(2)
        hl.addWidget(self.bar)
        hl.addWidget(self.plus)
        hl.addStretch(1)
        lay.addWidget(head)
        lay.addWidget(self.stack, 1)
        self._lay = lay
        self.bar.tabCloseRequested.connect(self.tabCloseRequested)
        self.bar.currentChanged.connect(self._changed)
        self.bar.tabMoved.connect(lambda a, b: self._w.insert(b, self._w.pop(a)))

    def set_toolbar(self, w):
        self._lay.insertWidget(1, w)

    def set_extra_bar(self, w):
        self._lay.insertWidget(2, w)

    def _changed(self, i):
        if 0 <= i < len(self._w):
            self.stack.setCurrentWidget(self._hold[self._w[i]])
        self.currentChanged.emit(i)

    def addTab(self, w, text):
        self._w.append(w)
        hold = Holder(w, self.letterbox)
        self._hold[w] = hold
        self.stack.addWidget(hold)
        return self.bar.addTab(text)

    def removeTab(self, i):
        w = self._w.pop(i)
        hold = self._hold.pop(w, None)
        if hold is not None:
            self.stack.removeWidget(hold)
            hold.deleteLater()
        self.bar.removeTab(i)

    def moveTab(self, a, b):
        self._w.insert(b, self._w.pop(a))
        self.bar.blockSignals(True)
        self.bar.moveTab(a, b)
        self.bar.blockSignals(False)

    def count(self):
        return len(self._w)

    def widget(self, i):
        return self._w[i] if 0 <= i < len(self._w) else None

    def indexOf(self, w):
        return self._w.index(w) if w in self._w else -1

    def currentIndex(self):
        return self.bar.currentIndex()

    def currentWidget(self):
        return self.widget(self.bar.currentIndex())

    def setCurrentIndex(self, i):
        self.bar.setCurrentIndex(i)

    def setTabText(self, i, t):
        self.bar.setTabText(i, t)
        self.bar.setTabToolTip(i, t)

    def setTabIcon(self, i, ic):
        self.bar.setTabIcon(i, ic)

    def setTabsClosable(self, b):
        self.bar.setTabsClosable(b)

    def tabBar(self):
        return self.bar


# ------------------------------------------------------------------ VPN / antivirus / panic-wipe helpers
def active_vpn_url():
    for p in SETTINGS["vpn_profiles"]:
        if p.get("name") == SETTINGS["vpn_active"]:
            return p.get("url", "")
    return ""


def find_wireguard():
    if sys.platform != "win32":
        return None
    for base in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")):
        p = Path(base) / "WireGuard" / "wireguard.exe"
        if base and p.is_file():
            return p
    return None


def shell_runas(exe, params):
    """Run a program elevated (Windows UAC prompt)."""
    if sys.platform != "win32":
        return False
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", str(exe), params, None, 0) > 32


def find_defender():
    """Microsoft Defender's command-line scanner (built into Windows)."""
    if sys.platform != "win32":
        return None
    cands = []
    plat = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if plat.exists():
        cands += sorted(plat.glob("*/MpCmdRun.exe"))[::-1]
    cands.append(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Windows Defender" / "MpCmdRun.exe")
    return next((c for c in cands if c.is_file()), None)


def add_motw(path, url):
    """Mark the file as downloaded from the internet (Windows 'Mark of the Web')."""
    if sys.platform != "win32":
        return
    try:
        with open(str(path) + ":Zone.Identifier", "w", encoding="ascii", errors="ignore") as f:
            f.write(f"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={url}\r\n")
    except OSError:
        pass


def av_verdict(rep):
    vt = rep.get("vt")
    mal = vt.get("malicious", 0) if isinstance(vt, dict) else 0
    sus = vt.get("suspicious", 0) if isinstance(vt, dict) else 0
    if rep["defender"] == "threat" or mal >= 3:
        return "threat"
    if rep["flags"] or mal >= 1 or sus >= 3:
        return "suspicious"
    return "clean"


def secure_delete(p):
    """Overwrite small files with random bytes, then delete (best effort - SSD wear-levelling can keep copies)."""
    p = Path(p)
    try:
        if p.is_file() and not p.is_symlink():
            size = p.stat().st_size
            if 0 < size <= 8 * 1024 * 1024:
                with open(p, "r+b") as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
        p.unlink(missing_ok=True)
    except OSError:
        pass


def wipe_path(p):
    p = Path(p)
    if p.is_dir() and not p.is_symlink():
        for sub in sorted(p.rglob("*"), key=lambda x: len(x.parts), reverse=True):
            if sub.is_dir() and not sub.is_symlink():
                try:
                    sub.rmdir()
                except OSError:
                    pass
            else:
                secure_delete(sub)
        try:
            p.rmdir()
        except OSError:
            pass
    else:
        secure_delete(p)


def run_wipe_helper():
    """Detached helper started by Panic Wipe: waits for Nova to exit, then deletes everything (retrying locked files)."""
    try:
        job = Path(sys.argv[sys.argv.index("--wipe") + 1])
        data = json.loads(job.read_text(encoding="utf-8"))
        job.unlink(missing_ok=True)
    except Exception:
        return
    try:
        psutil.wait_procs([psutil.Process(data["pid"])], timeout=30)
    except psutil.Error:
        pass
    for _ in range(30):
        left = [p for p in data["paths"] if Path(p).exists()]
        if not left:
            break
        for p in left:
            wipe_path(p)
        time.sleep(0.5)
    if sys.platform == "win32":
        flags = 0x08000000
        try:
            recent = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
            names = {n.lower() for n in data.get("recent", [])}
            if recent.is_dir():
                for lnk in recent.glob("*.lnk"):            # "report.pdf.lnk" -> stem "report.pdf"
                    if lnk.stem.lower() in names:
                        secure_delete(lnk)
                if data.get("scorched"):                    # jump lists also remember recent files
                    for sub in ("AutomaticDestinations", "CustomDestinations"):
                        for f in (recent / sub).glob("*"):
                            secure_delete(f)
        except Exception:
            pass
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=flags)
        except Exception:
            pass
        if data.get("freespace"):                           # overwrite deleted data on the disk (slow)
            try:
                subprocess.run(["cipher", "/w:" + data["freespace"]], capture_output=True, creationflags=flags,
                               timeout=6 * 3600)
            except Exception:
                pass


def panic_targets():
    t = [Path(QStandardPaths.writableLocation(loc)) / "QtWebEngine"          # cookies, cache, site data (all profiles)
         for loc in (QStandardPaths.StandardLocation.AppDataLocation, QStandardPaths.StandardLocation.CacheLocation)]
    scorched = bool(SETTINGS["panic_scorched"])
    if scorched:
        t.append(ROOT_DATA)                                  # every profile, vault, settings, quarantine, VPN configs…
    else:
        t += [HISTORY_FILE, SESSION_FILE, WORKSPACES_FILE, DOWNLOADS_LOG, FLOW_FILE, PIN_FILE, DATA_TOR,
              DATA / "deals.json", DATA / "update.json"]
        if SETTINGS["panic_bookmarks"]:
            t.append(BOOKMARKS_FILE)
    if scorched or SETTINGS["panic_screenshots"]:
        t.append(SHOT_DIR)
    if scorched or SETTINGS["panic_downloads"]:
        t += [Path(p) for p in load_json(DOWNLOADS_LOG, [])]
    return [str(x) for x in t]


def kill_nova_processes():
    me = os.getpid()
    for p in psutil.process_iter(["pid", "exe", "cmdline"]):
        try:
            if p.pid == me:
                continue
            cl = " ".join(p.info["cmdline"] or [])
            if "--wipe" in cl:
                continue
            same_exe = IS_FROZEN and p.info["exe"] and Path(p.info["exe"]) == Path(sys.executable)
            if same_exe or "nova_browser" in cl:
                for c in p.children(recursive=True):
                    c.kill()
                p.kill()
        except psutil.Error:
            pass
    for c in psutil.Process().children(recursive=True):
        try:
            c.kill()
        except psutil.Error:
            pass


def quarantine(path, rep, why):
    key = (rep.get("sha256") or hashlib.sha256(str(path).encode()).hexdigest())[:16]
    shutil.move(str(path), str(QUAR_DIR / f"{key}.quar"))
    save_json(QUAR_DIR / f"{key}.json", {"orig": str(path), "why": why, "report": rep})


class ScanThread(QThread):
    """Antivirus check: file heuristics + Microsoft Defender + optional VirusTotal hash lookup."""
    done = pyqtSignal(dict)

    def __init__(self, path, vt_key=None):
        super().__init__()
        self.path, self.vt_key = Path(path), vt_key

    def run(self):
        rep = {"path": str(self.path), "sha256": "", "defender": "n/a", "vt": None, "flags": [],
               "dir": self.path.is_dir()}
        try:
            if not rep["dir"]:
                h = hashlib.sha256()
                with open(self.path, "rb") as f:
                    head = f.read(4096)
                    h.update(head)
                    while True:
                        c = f.read(1 << 20)
                        if not c:
                            break
                        h.update(c)
                rep["sha256"] = h.hexdigest()
                name, ext = self.path.name.lower(), self.path.suffix.lower()
                if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\."
                             r"(exe|scr|bat|cmd|js|vbs|ps1|lnk|com|hta)$", name):
                    rep["flags"].append("double extension - an executable disguised as a document")
                if head[:2] == b"MZ" and ext not in (".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".ocx"):
                    rep["flags"].append(f"Windows program disguised as {ext or 'a data file'}")
            mp = find_defender()
            if mp:
                try:
                    r = subprocess.run([str(mp), "-Scan", "-ScanType", "3", "-File", str(self.path),
                                        "-DisableRemediation"], capture_output=True, timeout=300,
                                       creationflags=0x08000000 if sys.platform == "win32" else 0)
                    rep["defender"] = "clean" if r.returncode == 0 else "threat" if r.returncode == 2 else "error"
                except Exception:
                    rep["defender"] = "error"
            else:
                rep["defender"] = "unavailable"
            if self.vt_key and rep["sha256"]:
                try:
                    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{rep['sha256']}",
                                                 headers={"x-apikey": self.vt_key})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        st = json.load(r)["data"]["attributes"]["last_analysis_stats"]
                    rep["vt"] = {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0)}
                except urllib.error.HTTPError as e:
                    rep["vt"] = "unknown" if e.code == 404 else "error"
                except Exception:
                    rep["vt"] = "error"
        except Exception as e:
            rep["error"] = str(e)
        self.done.emit(rep)


class QuarantineDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Quarantine")
        self.resize(560, 360)
        lay = QVBoxLayout(self)
        self.list = QListWidget()
        lay.addWidget(self.list)
        row = QHBoxLayout()
        for t, f in (("Restore", self.restore), ("Delete permanently", self.delete)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, f=f: f())
            row.addWidget(b)
        lay.addLayout(row)
        self.refresh()

    def metas(self):
        return sorted(QUAR_DIR.glob("*.json"))

    def refresh(self):
        self.list.clear()
        for m in self.metas():
            d = load_json(m, {})
            self.list.addItem(f"{Path(d.get('orig', '?')).name} — {d.get('why', '')}")

    def sel(self):
        r, ms = self.list.currentRow(), self.metas()
        return ms[r] if 0 <= r < len(ms) else None

    def delete(self):
        m = self.sel()
        if m:
            secure_delete(m.with_suffix(".quar"))
            m.unlink(missing_ok=True)
            self.refresh()

    def restore(self):
        m = self.sel()
        if not m:
            return
        if QMessageBox.warning(self, "Quarantine", "This file was flagged as dangerous. Restore anyway?",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        d = load_json(m, {})
        dest = Path(d.get("orig", ""))
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(m.with_suffix(".quar")), str(dest))
        m.unlink(missing_ok=True)
        self.refresh()


class VpnDock(QDockWidget):
    """Two real VPN clients: (1) proxy VPN for Nova's traffic, (2) WireGuard manager for the whole PC.
    Nova does not provide VPN servers - you bring a provider (Mullvad, Proton, IVPN, ...)."""

    def __init__(self, browser):
        super().__init__("VPN", browser)
        self.b = browser
        w = QWidget(); lay = QVBoxLayout(w)
        self.status = QLabel(); self.status.setWordWrap(True)
        lay.addWidget(self.status)

        g = QGroupBox("1 · Proxy VPN (Nova's traffic only)"); l = QVBoxLayout(g)
        self.combo = QComboBox(); l.addWidget(self.combo)
        for pair in ((("Add…", self.add_profile), ("Delete", self.del_profile)),
                     (("Use (restarts Nova)", self.use_profile), ("Turn off", self.turn_off))):
            r = QHBoxLayout()
            for t, f in pair:
                b = QPushButton(t); b.clicked.connect(lambda _=False, f=f: f()); r.addWidget(b)
            l.addLayout(r)
        n = QLabel("Enter the HTTPS or SOCKS5 proxy from your VPN provider. If it's unreachable, pages fail "
                   "instead of leaking, and DNS goes through the proxy. Chromium can't log in to SOCKS5 proxies - "
                   "for those providers use their HTTPS proxy or WireGuard below.")
        n.setWordWrap(True); l.addWidget(n)
        lay.addWidget(g)

        g = QGroupBox("2 · WireGuard (whole computer)"); l = QVBoxLayout(g)
        self.wg = QComboBox(); l.addWidget(self.wg)
        for pair in ((("Import .conf…", self.import_conf), ("Get WireGuard", lambda: self.b.new_tab("https://www.wireguard.com/install/"))),
                     (("Connect", self.connect_wg), ("Disconnect", self.disconnect_wg))):
            r = QHBoxLayout()
            for t, f in pair:
                b = QPushButton(t); b.clicked.connect(lambda _=False, f=f: f()); r.addWidget(b)
            l.addLayout(r)
        n = QLabel("Needs WireGuard for Windows (free). Connecting asks for administrator permission. With "
                   "AllowedIPs = 0.0.0.0/0 WireGuard blocks traffic outside the tunnel (kill switch). The .conf holds "
                   "your private key - keep this PC's disk encrypted.")
        n.setWordWrap(True); l.addWidget(n)
        lay.addWidget(g)

        b = QPushButton("Check my IP / DNS / WebRTC leaks")
        b.clicked.connect(lambda _=False: self.b.new_tab("https://ipleak.net"))
        lay.addWidget(b)
        lay.addStretch()
        self.setWidget(w)
        self.refresh()

    def wg_up(self):
        name = self.wg.currentText().lower()
        if not name:
            return False
        try:
            return any(name in k.lower() and v.isup for k, v in psutil.net_if_stats().items())
        except Exception:
            return False

    def refresh(self):
        self.combo.clear()
        self.combo.addItems([p["name"] for p in SETTINGS["vpn_profiles"]])
        if SETTINGS["vpn_active"]:
            self.combo.setCurrentText(SETTINGS["vpn_active"])
        cur = self.wg.currentText()
        self.wg.clear()
        self.wg.addItems(sorted(p.stem for p in VPN_DIR.glob("*.conf")))
        if cur:
            self.wg.setCurrentText(cur)
        px = f"Proxy VPN: ON ({SETTINGS['vpn_active']})" if active_vpn_url() else "Proxy VPN: off"
        wg = "WireGuard: connected" if self.wg_up() else "WireGuard: not connected"
        self.status.setText(f"<b>{px}</b><br><b>{wg}</b>")

    def add_profile(self):
        name, ok = QInputDialog.getText(self, "VPN profile", "Name (e.g. Mullvad NL):")
        if not ok or not name.strip():
            return
        url, ok = QInputDialog.getText(self, "VPN profile",
                                       "Proxy URL: socks5://host:1080  or  https://host:443  or  http://host:8080")
        if not ok or not re.match(r"^(socks5|socks4|http|https)://[^\s/]+:\d+$", url.strip()):
            QMessageBox.warning(self, "VPN", "That doesn't look like a proxy URL (scheme://host:port).")
            return
        user, ok = QInputDialog.getText(self, "VPN profile", "Username (leave blank if none):")
        pw = ""
        if ok and user.strip():
            pw, _ = QInputDialog.getText(self, "VPN profile", "Password:", QLineEdit.EchoMode.Password)
        name = name.strip()
        SETTINGS["vpn_profiles"] = [p for p in SETTINGS["vpn_profiles"] if p["name"] != name] + [{"name": name, "url": url.strip()}]
        save_settings()
        if ok and user.strip():
            self.b.store_vpn_creds(name, user.strip(), pw)
        self.refresh()

    def del_profile(self):
        n = self.combo.currentText()
        SETTINGS["vpn_profiles"] = [p for p in SETTINGS["vpn_profiles"] if p["name"] != n]
        if SETTINGS["vpn_active"] == n:
            SETTINGS["vpn_active"] = ""
        save_settings()
        self.refresh()

    def use_profile(self):
        n = self.combo.currentText()
        if n:
            SETTINGS["vpn_active"] = n
            save_settings()
            self.b.restart_app()

    def turn_off(self):
        SETTINGS["vpn_active"] = ""
        save_settings()
        self.b.restart_app()

    def import_conf(self):
        f, _ = QFileDialog.getOpenFileName(self, "WireGuard config", "", "WireGuard (*.conf)")
        if not f:
            return
        if "PrivateKey" not in Path(f).read_text(encoding="utf-8", errors="ignore"):
            QMessageBox.warning(self, "VPN", "This doesn't look like a WireGuard config.")
            return
        name = re.sub(r"[^A-Za-z0-9_=+.-]", "_", Path(f).stem)[:32]
        shutil.copy(f, VPN_DIR / f"{name}.conf")
        self.refresh()
        self.wg.setCurrentText(name)

    def connect_wg(self):
        exe, name = find_wireguard(), self.wg.currentText()
        if not exe:
            QMessageBox.information(self, "VPN", "Install WireGuard for Windows first (button above).")
            return
        if name and shell_runas(exe, f'/installtunnelservice "{VPN_DIR / (name + ".conf")}"'):
            self.status.setText("<b>Connecting…</b>")
            QTimer.singleShot(5000, self.refresh)
        elif name:
            QMessageBox.warning(self, "VPN", "Couldn't start the tunnel. Import the same .conf in the WireGuard app instead.")

    def disconnect_wg(self):
        exe, name = find_wireguard(), self.wg.currentText()
        if exe and name and shell_runas(exe, f"/uninstalltunnelservice {name}"):
            QTimer.singleShot(4000, self.refresh)


# ------------------------------------------------------------------ main window
class Browser(QMainWindow):
    def __init__(self, private=False, tor=False, tor_exe=None, start_urls=None):
        super().__init__()
        self.tor, self.tor_exe, self.tor_proc, self.tor_done = tor, tor_exe, None, False
        private = private or tor
        self.private = private
        self.ephemeral = private or SETTINGS["paranoid"]     # nothing about this window is saved
        self.profile = make_profile(private)
        self.bookmarks = load_json(BOOKMARKS_FILE, [])
        self.history = [] if self.ephemeral else load_json(HISTORY_FILE, [])
        self.closed, self._threads, self._procs, self._dev, self._floats = [], [], {}, [], []
        self._secrets = {}
        self.dl_items = []
        self._gsb_seen = set()
        self._island_seq = -1
        self.setWindowTitle("Nova Browser" + (" — Tor" if tor else " — Private" if private else ""))
        self.resize(1360, 860)

        self.sfx = {}
        if HAVE_AUDIO:
            make_sounds()
            for n in ("click", "open", "close"):
                e = QSoundEffect(self)
                e.setSource(QUrl.fromLocalFile(str(SOUND_DIR / f"{n}.wav")))
                e.setVolume(0.5)
                self.sfx[n] = e

        self.tabs = TabArea(letterbox=self.tor or SETTINGS["letterbox"])
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.tabs.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabs.tabBar().customContextMenuRequested.connect(self.tab_menu)
        self.setCentralWidget(self.tabs)
        self.tabs.plus.clicked.connect(lambda _=False: self.new_tab())

        self.build_toolbar()
        self.build_sidebar()
        self.build_findbar()
        self.build_panel()
        self.side = SidePanel(self)
        self.music = MusicDock(self)
        self.assistant = AssistantDock(self)
        self.vpn = VpnDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.vpn)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.panel)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.side)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.assistant)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.music)
        self.panel.hide(); self.side.hide(); self.music.hide(); self.assistant.hide(); self.vpn.hide()
        self.build_shortcuts()

        self.profile.downloadRequested.connect(self.on_download)
        SHIELDS.blocked.connect(self.update_shield_label)
        self.apply_scripts()

        self.timer = QTimer(self, interval=5000)
        self.timer.timeout.connect(self.resource_tick)
        self.timer.start()
        self.chroma = None
        if SETTINGS["chroma"]:
            self.start_chroma()

        if self.tor:
            self.start_tor()
        else:
            urls = load_json(SESSION_FILE, []) if (SETTINGS["restore_session"] and not self.ephemeral) else []
            if not SETTINGS["welcomed"] and not self.ephemeral:
                SETTINGS["welcomed"] = True
                save_settings()
                self.new_tab(html=WELCOME_HTML)
            for u in urls + list(start_urls or []):
                self.new_tab(u)
            if not self.tabs.count():
                self.new_tab()
            if not private:
                QTimer.singleShot(8000, lambda: self.check_updates())

    # ================================================================ UI
    def act(self, menu, text, fn, shortcut=None):
        a = menu.addAction(text)
        a.triggered.connect(lambda _=False, f=fn: f())
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        return a

    def build_toolbar(self):
        tb = QToolBar("Navigation", self)
        tb.setObjectName("nav")
        tb.setMovable(False)
        tb.setIconSize(QSize(20, 20))
        self.tabs.set_toolbar(tb)

        def tool(icon, tip, fn, color="#cfd0dc"):
            a = self.act(tb, "", fn)
            a.setIcon(svg_icon(icon, color))
            a.setToolTip(tip)
            return a
        tool("back", "Back (Alt+Left)", lambda: self.cur().back())
        tool("forward", "Forward (Alt+Right)", lambda: self.cur().forward())
        tool("reload", "Reload (F5)", lambda: self.cur().reload())
        tool("home", "Home", self.go_home)

        self.urlbar = QLineEdit(placeholderText="Search or enter address")
        self.urlbar.setObjectName("omnibox")
        self.urlbar.setClearButtonEnabled(True)
        self.urlbar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.lock_action = self.urlbar.addAction(svg_icon("search", "#8a8a99"), QLineEdit.ActionPosition.LeadingPosition)
        self.star_action = self.urlbar.addAction(svg_icon("star", "#8a8a99"), QLineEdit.ActionPosition.TrailingPosition)
        self.star_action.setToolTip("Bookmark this page (Ctrl+D)")
        self.star_action.triggered.connect(lambda _=False: self.add_bookmark())
        self.urlbar.returnPressed.connect(self.navigate)
        tb.addWidget(self.urlbar)

        self.shield_btn = QToolButton()
        self.shield_btn.setObjectName("shield")
        self.shield_btn.setIcon(svg_icon("shield", theme()[0]))
        self.shield_btn.setText("0")
        self.shield_btn.setToolTip("Shields — blocked trackers & site controls")
        self.shield_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.shield_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        sm = QMenu(self.shield_btn)
        sm.aboutToShow.connect(lambda: (sm.clear(), self.fill_shield_menu(sm)))
        self.shield_btn.setMenu(sm)
        tb.addWidget(self.shield_btn)

        self.tor_label = QLabel("")
        tb.addWidget(self.tor_label)

        dl = QToolButton()
        dl.setIcon(svg_icon("download"))
        dl.setToolTip("Downloads")
        dl.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        dm = QMenu(dl)
        dm.aboutToShow.connect(lambda: (dm.clear(), self.fill_downloads(dm)))
        dl.setMenu(dm)
        tb.addWidget(dl)

        tool("network", "VPN", lambda: self.toggle(self.vpn))
        if self.tor:
            tool("globe", "New Tor identity", self.new_identity)
        else:
            tool("globe", "New Tor window", self.open_tor)
        tool("alert", "PANIC WIPE — erase activity & close (Ctrl+Shift+Backspace)",
             lambda: self.panic(True), "#ff5470")
        btn = QToolButton()
        btn.setIcon(svg_icon("menu"))
        btn.setToolTip("Menu")
        btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        btn.setMenu(self.build_menu(btn))
        tb.addWidget(btn)

        self.sugg_model = QStringListModel(self)
        comp = QCompleter(self.sugg_model, self)
        comp.setCompletionMode(QCompleter.CompletionMode.UnfilteredPopupCompletion)
        comp.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        comp.activated.connect(lambda txt: (self.urlbar.setText(txt), self.navigate()))
        self.urlbar.setCompleter(comp)
        self.urlbar.textEdited.connect(self.update_suggestions)

        self.bm_bar = QToolBar("Bookmarks", self)
        self.bm_bar.setObjectName("bmbar")
        self.bm_bar.setMovable(False)
        self.bm_bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.bm_bar.setIconSize(QSize(14, 14))
        self.tabs.set_extra_bar(self.bm_bar)
        self.refresh_bookmarks_bar(True)

    def fill_shield_menu(self, m):
        t = self.cur()
        host = t.url().host().lower() if t else ""
        head = m.addAction(f"Shields · {host or 'this page'}")
        head.setEnabled(False)
        m.addSeparator()
        off = bool(host and host in SHIELDS.off)
        self.act(m, "Shields are OFF here — turn on" if off else "Shields are ON — turn off for this site",
                 self.toggle_site_shield)
        self.act(m, "JavaScript is ON — block it on this site" if self.js_allowed(host)
                 else "JavaScript is BLOCKED — allow it", self.toggle_js)
        muted = t.page().isAudioMuted() if t else False
        self.act(m, "Unmute this tab" if muted else "Mute this tab", self.toggle_mute)
        m.addSeparator()
        info = m.addAction(f"{SHIELDS.count} trackers & ads blocked this session")
        info.setEnabled(False)
        self.act(m, "Open settings", lambda: self.toggle(self.panel))

    def fill_downloads(self, m):
        for d in reversed(self.dl_items[-8:]):
            self.act(m, d["name"][:48], lambda p=d["path"]: open_folder(Path(p).parent))
        if not self.dl_items:
            m.addAction("No downloads yet").setEnabled(False)
        else:
            m.addSeparator()
        self.act(m, "Open downloads folder", lambda: open_folder(Path.home() / "Downloads"))

    def dyn(self, parent, title, filler):
        sub = parent.addMenu(title)
        sub.aboutToShow.connect(lambda: (sub.clear(), filler(sub)))
        return sub

    def build_menu(self, parent):
        m = QMenu(parent)
        self.act(m, "New tab", lambda: self.new_tab(), "Ctrl+T")
        self.act(m, "New private window", self.open_private, "Ctrl+Shift+N")
        self.act(m, "New Tor window", self.open_tor)
        self.act(m, "Reopen closed tab", self.reopen_tab, "Ctrl+Shift+T")
        m.addSeparator()
        self.dyn(m, "Bookmarks", self.fill_bookmarks)
        self.dyn(m, "History", self.fill_history)
        self.dyn(m, "Workspaces", self.fill_workspaces)
        self.act(m, "Restore last session", self.restore_session)
        self.act(m, "Open downloads folder", lambda: open_folder(Path.home() / "Downloads"))
        m.addSeparator()
        pm = m.addMenu("Page")
        self.act(pm, "Find in page", self.show_find, "Ctrl+F")
        self.act(pm, "Reader mode (Speedreader)", self.reader_mode)
        self.act(pm, "Print / save as PDF", self.print_pdf, "Ctrl+P")
        self.act(pm, "Screenshot", self.screenshot)
        self.act(pm, "Zoom in", lambda: self.zoom(0.1), "Ctrl+=")
        self.act(pm, "Zoom out", lambda: self.zoom(-0.1), "Ctrl+-")
        self.act(pm, "Reset zoom", lambda: self.zoom(0), "Ctrl+0")
        self.act(pm, "Developer tools", self.open_devtools, "F12")
        xm = m.addMenu("Extensions & mods")
        self.act(xm, "Manage extensions…", self.open_extensions)
        self.act(xm, "Open userscripts folder", lambda: open_folder(USERSCRIPT_DIR))
        self.act(xm, "Open mods (custom CSS) folder", lambda: open_folder(MODS_DIR))
        self.act(xm, "Reload scripts & mods", self.apply_scripts)
        fm = m.addMenu("Filter lists")
        self.act(fm, "Import filter list…", self.import_filter)
        self.act(fm, "Download EasyList + EasyPrivacy + malware list", self.update_filters)
        self.act(fm, "Open filters folder", lambda: open_folder(FILTER_DIR))
        sec = m.addMenu("Security & privacy")
        self.act(sec, "Maximum privacy preset", lambda: self.apply_preset("Maximum privacy"))
        self.act(sec, "Balanced preset", lambda: self.apply_preset("Balanced"))
        self.act(sec, "Vault (passwords)…", self.open_vault)
        self.act(sec, "Set / change master password…", self.set_master_password)
        self.act(sec, "Encrypted backup — export…", self.export_backup)
        self.act(sec, "Encrypted backup — import…", self.import_backup)
        self.dyn(sec, "Privacy test sites", self.fill_tests)
        self.act(sec, "🚨 Panic: wipe & exit  (Ctrl+Shift+Backspace)", self.panic)
        av = m.addMenu("Antivirus")
        self.act(av, "Scan a file…", self.scan_pick_file)
        self.act(av, "Scan Downloads folder", self.scan_downloads)
        self.act(av, "Quarantine…", self.open_quarantine)
        self.act(av, "Set VirusTotal key…", lambda: self.get_secret("vt_key", "VirusTotal API key", force=True))
        self.act(m, "VPN…", lambda: self.toggle(self.vpn))
        self.act(m, "Floating video", self.float_video)
        self.act(m, "Ask Claude (opt-in)", lambda: self.toggle(self.assistant))
        self.act(m, "GX Corner (game deals)", self.gx_corner)
        m.addSeparator()
        self.act(m, "Export bookmarks…", self.export_bookmarks)
        self.act(m, "Import bookmarks…", self.import_bookmarks)
        lib = m.addMenu("Library & tools")
        self.act(lib, "Bookmarks manager\tCtrl+Shift+O", lambda: self.open_library(0))
        self.act(lib, "History\tCtrl+H", lambda: self.open_library(1))
        self.act(lib, "Pinboards", lambda: self.open_library(2))
        self.act(lib, "Flow (notes & links)", lambda: self.open_library(3))
        self.act(lib, "Downloads manager\tCtrl+J", lambda: self.open_library(4))
        self.act(lib, "Site permissions", lambda: self.open_library(5))
        lib.addSeparator()
        self.act(lib, "Pin this page…", self.pin_page)
        self.act(lib, "Send this page to Flow", lambda: self.flow_add(self.cur().url().toString(), "link"))
        self.act(lib, "Search tabs\tCtrl+Shift+A", self.tab_search)
        self.act(lib, "Command palette\tCtrl+Shift+P", self.command_palette)
        self.act(lib, "Show / hide bookmarks bar\tCtrl+Shift+B", self.toggle_bookmarks_bar)
        lib.addSeparator()
        self.act(lib, "Translate this page…", self.translate_page)
        self.act(lib, "View page source\tCtrl+U", self.view_source)
        self.act(lib, "Save page as…\tCtrl+S", self.save_page)
        self.act(lib, "Autofill: addresses & cards…", self.open_autofill)
        self.act(lib, "Extensions…", self.open_extensions)
        self.act(lib, "Sidebar apps…", self.open_sidebar_apps)
        self.dyn(m, "Profiles", self.fill_profiles)
        self.act(m, "Security checkup", self.security_checkup)
        self.act(m, "Settings", lambda: self.toggle(self.panel))
        self.act(m, "Make Nova the default browser", self.make_default)
        self.act(m, "Check for updates", lambda: self.check_updates(True))
        self.act(m, "About Nova", self.about)
        return m

    @property
    def SIDEBAR(self):
        chosen = SETTINGS["sidebar_apps"]
        apps = [(s, n, u, m) for s, n, u, m, c in APP_CATALOG if s in chosen]
        return apps + [(a["short"], a["name"], a["url"], "tab") for a in SETTINGS["custom_apps"]]

    def app_color(self, short):
        for s, n, u, m, c in APP_CATALOG:
            if s == short:
                return c
        return BRAND.get(short, "#2a2a38")

    def build_sidebar(self):
        self.sb = QToolBar("Sidebar", self)
        self.sb.setObjectName("sidebar")
        self.sb.setOrientation(Qt.Orientation.Vertical)
        self.sb.setMovable(False)
        self.sb.setIconSize(QSize(28, 28))
        self.addToolBar(Qt.ToolBarArea.LeftToolBarArea, self.sb)
        self.fill_sidebar()

    def fill_sidebar(self):
        sb = self.sb
        sb.clear()
        for short, name, url, mode in self.SIDEBAR:
            a = self.act(sb, "", (lambda u=url: self.open_panel(u)) if mode == "panel"
                         else (lambda u=url: self.new_tab(u)))
            a.setIcon(badge_icon(short, self.app_color(short)))
            a.setToolTip(name + (" (side panel)" if mode == "panel" else ""))
        self.act(sb, "", self.open_sidebar_apps).setIcon(svg_icon("plus", "#b9bac8", 22))
        sb.actions()[-1].setToolTip("Add or remove sidebar apps")
        sb.addSeparator()
        for icon, tip, fn in (("star", "Library — bookmarks, history, pinboards, Flow", lambda: self.open_library(0)),
                              ("search", "Search tabs (Ctrl+Shift+A)", self.tab_search),
                              ("sliders", "Settings", lambda: self.toggle(self.panel)),
                              ("music", "Music & media controls", lambda: self.toggle(self.music)),
                              ("panel", "Side panel / split view", lambda: self.toggle(self.side)),
                              ("trash", "Cleaner", self.clean),
                              ("camera", "Screenshot", self.screenshot),
                              ("book", "Reader mode", self.reader_mode),
                              ("gamepad", "GX Corner", self.gx_corner),
                              ("pip", "Floating video (picture-in-picture)", self.float_video),
                              ("sparkles", "Ask Claude (opt-in)", lambda: self.toggle(self.assistant)),
                              ("key", "Vault", self.open_vault),
                              ("shield-check", "Antivirus — scan a file", self.scan_pick_file)):
            a = self.act(sb, "", fn)
            a.setIcon(svg_icon(icon, "#b9bac8", 22))
            a.setToolTip(tip)

    def toggle(self, dock):
        dock.setVisible(not dock.isVisible())

    def open_panel(self, url):
        self.side.open(url)

    def build_findbar(self):
        self.findbar = QToolBar("Find", self)
        self.find_edit = QLineEdit(placeholderText="Find in page")
        self.find_edit.textChanged.connect(lambda t: self.cur().findText(t))
        self.find_edit.returnPressed.connect(lambda: self.cur().findText(self.find_edit.text()))
        self.findbar.addWidget(self.find_edit)
        self.act(self.findbar, "▲", lambda: self.cur().findText(self.find_edit.text(), QWebEnginePage.FindFlag.FindBackward))
        self.act(self.findbar, "▼", lambda: self.cur().findText(self.find_edit.text()))
        self.act(self.findbar, "✕", self.hide_find)
        self.addToolBar(Qt.ToolBarArea.BottomToolBarArea, self.findbar)
        self.findbar.hide()

    def show_find(self):
        self.findbar.show(); self.find_edit.setFocus(); self.find_edit.selectAll()

    def hide_find(self):
        self.cur().findText("")
        self.findbar.hide()

    def build_shortcuts(self):
        def add(seq, fn):
            a = QAction(self); a.setShortcut(QKeySequence(seq))
            a.triggered.connect(lambda _=False, f=fn: f()); self.addAction(a)
        add("Ctrl+W", lambda: self.close_tab(self.tabs.currentIndex()))
        add("Ctrl+L", lambda: (self.urlbar.setFocus(), self.urlbar.selectAll()))
        add("Ctrl+D", self.add_bookmark)
        add("F5", lambda: self.cur().reload())
        add("F11", lambda: self.showNormal() if self.isFullScreen() else self.showFullScreen())
        add("Ctrl+Tab", lambda: self.tabs.setCurrentIndex((self.tabs.currentIndex() + 1) % self.tabs.count()))
        add("Ctrl+Shift+Tab", lambda: self.tabs.setCurrentIndex((self.tabs.currentIndex() - 1) % self.tabs.count()))
        add("Ctrl+Shift+Backspace", self.panic)
        add("Ctrl+Shift+A", self.tab_search)
        add("Ctrl+Shift+P", self.command_palette)
        add("Ctrl+Shift+B", self.toggle_bookmarks_bar)
        add("Ctrl+Shift+O", lambda: self.open_library(0))
        add("Ctrl+H", lambda: self.open_library(1))
        add("Ctrl+J", lambda: self.open_library(4))
        add("Ctrl+U", self.view_source)
        add("Ctrl+S", self.save_page)
        add("Esc", lambda: self.hide_find() if self.findbar.isVisible() else None)

    # ---------------------------------------------------------------- control panel
    def chk(self, layout, text, key, after=None):
        cb = QCheckBox(text); cb.setChecked(bool(SETTINGS[key]))

        def f(v):
            SETTINGS[key] = v; save_settings()
            if after:
                after(v)
        cb.toggled.connect(f); layout.addWidget(cb)
        return cb

    def chk_spin(self, layout, text, key, skey, lo, hi, suffix):
        row = QHBoxLayout()
        self.chk(row, text, key)
        sp = QSpinBox(); sp.setRange(lo, hi); sp.setSuffix(suffix); sp.setValue(int(SETTINGS[skey]))
        sp.valueChanged.connect(lambda v: (SETTINGS.__setitem__(skey, v), save_settings()))
        row.addWidget(sp); layout.addLayout(row)

    def build_panel(self):
        self.panel = QDockWidget("Settings", self)
        self.panel.setWidget(self.panel_content())

    def panel_content(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        w = QWidget(); root = QVBoxLayout(w)
        rescripts = lambda v: self.apply_scripts()

        g = QGroupBox("Presets"); l = QHBoxLayout(g)
        for name in PRESETS:
            b = QPushButton(name)
            b.clicked.connect(lambda _=False, n=name: self.apply_preset(n))
            l.addWidget(b)
        root.addWidget(g)

        g = QGroupBox("Shields"); l = QVBoxLayout(g)
        self.chk(l, "Block ads & trackers", "shield", rescripts)
        self.chk(l, "Upgrade to HTTPS (no HTTP fallback)", "https")
        self.chk(l, "Block third-party cookies", "block_3p_cookies")
        self.chk(l, "Strip tracking parameters (utm_, fbclid…)", "strip_params")
        self.chk(l, "Fingerprinting protection", "fingerprint", rescripts)
        self.chk(l, "Cosmetic filtering (hide ad slots)", "cosmetic", rescripts)
        self.chk(l, "Send Global Privacy Control / DNT", "gpc")
        self.chk(l, "Userscripts", "userscripts", rescripts)
        self.filter_label = QLabel(); self.filter_label.setWordWrap(True)
        l.addWidget(self.filter_label)
        b2 = QPushButton("Download EasyList + EasyPrivacy + malware list")
        b2.clicked.connect(lambda _=False: self.update_filters())
        b1 = QPushButton("Import filter list / hosts file…"); b1.clicked.connect(lambda _=False: self.import_filter())
        l.addWidget(b1); l.addWidget(b2)
        root.addWidget(g)
        self.update_filter_label()

        g = QGroupBox("Security & anti-tracking"); l = QVBoxLayout(g)
        self.chk(l, "Block popups that aren't user-initiated", "popup_block")
        self.chk(l, "Block autoplaying video/audio (restart)", "block_autoplay")
        self.chk(l, "Auto-reject cookie banners", "cookie_auto", rescripts)
        self.chk(l, "Google Safe Browsing check (sends page addresses to Google; your API key)", "gsb")
        self.chk(l, "Letterboxing: round the page size, Tor-style (restart)", "letterbox")
        self.chk(l, "Warn before risky downloads (.exe, .msi, .ps1…)", "dl_warn")
        self.chk(l, "Spoof screen size, UA data & WebGL", "spoof_screen", rescripts)
        self.chk(l, "Spoof timezone to UTC", "spoof_tz", rescripts)
        self.chk(l, "Disable WebRTC completely", "webrtc_off", rescripts)
        self.chk(l, "Clear cookies, cache & history on exit", "clear_on_exit")
        self.chk(l, "Paranoid mode: never write browsing data to disk (restart)", "paranoid")
        dc = QComboBox(); dc.addItems(list(DOH)); dc.setCurrentText(SETTINGS["doh"])
        dc.currentTextChanged.connect(lambda t: (SETTINGS.__setitem__("doh", t), save_settings()))
        l.addWidget(QLabel("Secure DNS / DoH (best-effort; restart)")); l.addWidget(dc)
        self.chk(l, "Use Widevine DRM if installed with Chrome/Edge (restart)", "drm")
        self.chk_spin(l, "Network limiter (experimental; restart)", "net_limit", "net_kbs", 16, 100000, " KB/s")
        root.addWidget(g)

        g = QGroupBox("Antivirus"); l = QVBoxLayout(g)
        self.chk(l, "Scan every download (Microsoft Defender + file checks)", "av_scan")
        self.chk(l, "Also look up file hashes on VirusTotal (your key; only the hash is sent)", "av_vt")
        for t, f in (("Scan a file…", self.scan_pick_file), ("Scan Downloads folder", self.scan_downloads),
                     ("Quarantine…", self.open_quarantine)):
            b = QPushButton(t); b.clicked.connect(lambda _=False, f=f: f()); l.addWidget(b)
        root.addWidget(g)

        g = QGroupBox("Panic Wipe  (Ctrl+Shift+Backspace)"); l = QVBoxLayout(g)
        self.chk(l, "Also delete files downloaded in Nova", "panic_downloads")
        self.chk(l, "Also delete Nova screenshots", "panic_screenshots")
        self.chk(l, "Also delete bookmarks", "panic_bookmarks")
        self.chk(l, "SCORCHED EARTH: delete everything Nova stored (all profiles, vault, settings)", "panic_scorched")
        self.chk(l, "Afterwards overwrite free disk space (slow, thorough)", "panic_freespace")
        b = QPushButton("🚨 Panic wipe now"); b.clicked.connect(lambda _=False: self.panic(True)); l.addWidget(b)
        root.addWidget(g)

        g = QGroupBox("Performance (GX Control)"); l = QVBoxLayout(g)
        self.ram_label = QLabel("RAM: …"); self.cpu_label = QLabel("CPU: …")
        l.addWidget(self.ram_label); l.addWidget(self.cpu_label)
        self.chk_spin(l, "RAM limiter", "ram_limit", "ram_mb", 300, 64000, " MB")
        self.chk_spin(l, "CPU limiter", "cpu_limit", "cpu_pct", 10, 100, " %")
        self.chk_spin(l, "Tab limiter", "tab_limit", "tab_max", 2, 100, " tabs")
        self.chk_spin(l, "Hot Tabs Killer", "autosleep", "autosleep_min", 1, 240, " min idle")
        self.chk(l, "Lower browser CPU priority", "low_priority")
        b = QPushButton("Sleep all background tabs now"); b.clicked.connect(lambda _=False: self.sleep_background())
        l.addWidget(b)
        root.addWidget(g)

        g = QGroupBox("Tor"); l = QVBoxLayout(g)
        lv = QComboBox(); lv.addItems(["Standard", "Safer", "Safest"]); lv.setCurrentText(SETTINGS["tor_level"])
        lv.currentTextChanged.connect(lambda t: (SETTINGS.__setitem__("tor_level", t), save_settings(),
                                                 self.cur().reload()))
        l.addWidget(QLabel("Tor security level (Safer = WebGL off, Safest = JavaScript off)")); l.addWidget(lv)
        br = QPlainTextEdit(SETTINGS["tor_bridges"])
        br.setPlaceholderText("obfs4 bridges, one per line (from bridges.torproject.org).\n"
                              "Hides that you use Tor. Restart the Tor window to apply.")
        br.setMaximumHeight(90)
        br.textChanged.connect(lambda: (SETTINGS.__setitem__("tor_bridges", br.toPlainText()), save_settings()))
        l.addWidget(QLabel("Tor bridges")); l.addWidget(br)
        root.addWidget(g)

        g = QGroupBox("Look & feel"); l = QVBoxLayout(g)
        tc = QComboBox(); tc.addItems(THEMES.keys()); tc.setCurrentText(SETTINGS["theme"])
        tc.currentTextChanged.connect(self.set_theme)
        l.addWidget(QLabel("Theme")); l.addWidget(tc)
        sc = QComboBox(); sc.addItems(ENGINES.keys()); sc.setCurrentText(SETTINGS["search"])
        sc.currentTextChanged.connect(lambda t: (SETTINGS.__setitem__("search", t), save_settings()))
        l.addWidget(QLabel("Search engine")); l.addWidget(sc)
        self.chk(l, "Force dark mode on websites", "force_dark", self.set_force_dark)
        self.chk(l, "UI sound effects", "sounds")
        self.chk(l, "Show bookmarks bar", "bookmarks_bar", lambda v: self.refresh_bookmarks_bar(True))
        self.chk(l, "Razer Chroma lighting (needs Razer Synapse)", "chroma", self.toggle_chroma)
        self.chk(l, "Restore last session on start", "restore_session")
        r = QHBoxLayout()
        wb = QPushButton("Wallpaper (image / .webm)…"); wb.clicked.connect(lambda _=False: self.pick_wallpaper())
        wc = QPushButton("Clear"); wc.clicked.connect(lambda _=False: self.pick_wallpaper(clear=True))
        r.addWidget(wb); r.addWidget(wc); l.addLayout(r)
        root.addWidget(g)

        g = QGroupBox("Ask Claude (opt-in)"); l = QVBoxLayout(g)
        self.chk(l, "Enable assistant (sends page text to Anthropic)", "ai_enabled")
        me = QLineEdit(SETTINGS["ai_model"])
        me.editingFinished.connect(lambda: (SETTINGS.__setitem__("ai_model", me.text().strip()), save_settings()))
        l.addWidget(QLabel("Model")); l.addWidget(me)
        root.addWidget(g)

        g = QGroupBox("Advanced"); l = QVBoxLayout(g)
        pe = QLineEdit(SETTINGS["proxy"]); pe.setPlaceholderText("socks5://127.0.0.1:1080  (restart to apply)")
        pe.editingFinished.connect(lambda: (SETTINGS.__setitem__("proxy", pe.text().strip()), save_settings()))
        l.addWidget(QLabel("Proxy / your own VPN's proxy")); l.addWidget(pe)
        ue = QLineEdit(SETTINGS["update_url"]); ue.setPlaceholderText("https://…/update.json")
        ue.editingFinished.connect(lambda: (SETTINGS.__setitem__("update_url", ue.text().strip()), save_settings()))
        l.addWidget(QLabel("Update manifest URL")); l.addWidget(ue)
        uk = QLineEdit(SETTINGS["update_pubkey"]); uk.setPlaceholderText("Update signing public key (base64)")
        uk.editingFinished.connect(lambda: (SETTINGS.__setitem__("update_pubkey", uk.text().strip()), save_settings()))
        l.addWidget(QLabel("Update public key (updates must be signed)")); l.addWidget(uk)
        self.chk(l, "Check for updates on start", "auto_update")
        ub = QPushButton("Check for updates now"); ub.clicked.connect(lambda _=False: self.check_updates(True))
        l.addWidget(ub)
        root.addWidget(g)
        root.addStretch()
        scroll.setWidget(w)
        return scroll

    def update_filter_label(self):
        spec = sum(len(v) for v in FILTERS.specific.values())
        self.filter_label.setText(f"{len(SHIELDS.allblock) + len(SHIELDS.hostsblock)} blocked domains · {len(FILTERS.generic)} generic + {spec} site-specific cosmetic rules")

    def set_theme(self, name):
        SETTINGS["theme"] = name; save_settings()
        apply_theme(QApplication.instance())
        self.chroma_update()

    def set_force_dark(self, on):
        attr = getattr(QWebEngineSettings.WebAttribute, "ForceDarkMode", None)
        if attr is None:
            QMessageBox.information(self, "Nova", "Forced dark mode needs Qt 6.7 or newer."); return
        self.profile.settings().setAttribute(attr, on)
        self.cur().reload()

    def pick_wallpaper(self, clear=False):
        for old in DATA.glob("wallpaper.*"):
            old.unlink(missing_ok=True)
        SETTINGS["wallpaper"] = ""
        if not clear:
            f, _ = QFileDialog.getOpenFileName(self, "Wallpaper", str(Path.home() / "Pictures"),
                                               "Images / video (*.png *.jpg *.jpeg *.webp *.gif *.webm *.mp4)")
            if f:
                dest = DATA / ("wallpaper" + Path(f).suffix.lower())
                shutil.copy(f, dest)
                SETTINGS["wallpaper"] = dest.name
        save_settings()

    # ================================================================ scripts / shields
    def install_script(self, name, source, point=None, world=None, frames=True):
        s = QWebEngineScript()
        s.setName("nova:" + name)
        s.setSourceCode(source)
        s.setInjectionPoint(point or QWebEngineScript.InjectionPoint.DocumentCreation)
        s.setWorldId(world if world is not None else QWebEngineScript.ScriptWorldId.MainWorld)
        s.setRunsOnSubFrames(frames)
        self.profile.scripts().insert(s)

    def apply_scripts(self):
        coll = self.profile.scripts()
        for s in coll.toList():
            if s.name().startswith("nova:"):
                coll.remove(s)
        off = json.dumps(sorted(SETTINGS["shields_off"]))
        if SETTINGS["shield"]:
            if SETTINGS["fingerprint"]:
                flags = json.dumps({"screen": SETTINGS["spoof_screen"], "tz": SETTINGS["spoof_tz"] or self.tor,
                                    "rtc": SETTINGS["webrtc_off"] or self.tor})
                self.install_script("fp", FP_JS.replace("__OFF__", off).replace("__FLAGS__", flags))
            if SETTINGS["cosmetic"]:
                self.install_script("cosmetic", COSMETIC_JS.replace("__OFF__", off)
                                    .replace("__GENERIC__", json.dumps(FILTERS.generic))
                                    .replace("__SPECIFIC__", json.dumps(FILTERS.specific)))
            if SETTINGS["cookie_auto"]:
                self.install_script("cookies", COOKIE_JS.replace("__OFF__", off),
                                    QWebEngineScript.InjectionPoint.DocumentReady)
        if SETTINGS["userscripts"]:
            for name, src, point in load_userscripts():
                self.install_script("us:" + name, src, point)
        for name, js in load_mods():
            self.install_script("mod:" + name, js)
        for name, js, point, frames in load_extension_scripts():     # isolated world, like real content scripts
            self.install_script("ext:" + name, js, point, QWebEngineScript.ScriptWorldId.ApplicationWorld, frames)

    def update_shield_label(self):
        self.shield_btn.setText(str(SHIELDS.count))

    def toggle_site_shield(self):
        host = self.cur().url().host().lower()
        if not host:
            return
        off = set(SETTINGS["shields_off"])
        off.symmetric_difference_update({host})
        SETTINGS["shields_off"] = sorted(off); save_settings()
        SHIELDS.off = off
        self.apply_scripts()
        self.update_site_shield()
        self.cur().reload()

    def update_site_shield(self):
        t = self.cur()
        url = t.url() if t else QUrl()
        host, acc = url.host().lower(), theme()[0]
        off = bool(host and host in SHIELDS.off)
        self.shield_btn.setIcon(svg_icon("shield-off" if off else "shield", "#8a8a99" if off else acc))
        scheme = url.scheme()
        if is_blank(url) or not scheme:
            self.lock_action.setIcon(svg_icon("search", "#8a8a99"))
            self.lock_action.setToolTip("")
        elif scheme == "https":
            self.lock_action.setIcon(svg_icon("lock", "#4ade80"))
            self.lock_action.setToolTip("Connection is encrypted (HTTPS)")
        else:
            self.lock_action.setIcon(svg_icon("unlock", "#ff5470"))
            self.lock_action.setToolTip("Not secure")
        starred = any(b["url"] == url.toString() for b in self.bookmarks)
        self.star_action.setIcon(svg_icon("star", acc if starred else "#8a8a99", fill=starred))
        self.refresh_bookmarks_bar()

    def import_filter(self):
        f, _ = QFileDialog.getOpenFileName(self, "Import filter list", "", "Filter lists (*.txt)")
        if f:
            shutil.copy(f, FILTER_DIR / Path(f).name)
            self.reload_filters()

    def reload_filters(self):
        FILTERS.load()
        SHIELDS.allblock = BUILTIN_BLOCK | FILTERS.block
        SHIELDS.hostsblock = FILTERS.hosts
        SHIELDS.badurls = FILTERS.badurls
        self.apply_scripts()
        self.update_filter_label()

    def net_blocked(self):
        if self.tor:
            QMessageBox.information(self, "Nova", "Network features that bypass Tor are disabled in Tor windows.")
            return True
        return False

    def run_thread(self, th):
        self._threads.append(th)
        th.finished.connect(lambda t=th: self._threads.remove(t) if t in self._threads else None)
        th.start()

    def update_filters(self):
        if self.net_blocked():
            return
        lists = [("https://easylist.to/easylist/easylist.txt", "easylist.txt"),
                 ("https://easylist.to/easylist/easyprivacy.txt", "easyprivacy.txt"),
                 ("https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus-malware-hosts.txt"),
                 ("https://openphish.com/feed.txt", "openphish-phishing.urls"),
                 ("https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", "fanboy-cookiemonster.txt")]
        left = [len(lists)]

        def ok(_):
            left[0] -= 1
            if left[0] == 0:
                self.reload_filters()
                self.statusBar().showMessage("Filter lists updated", 5000)
        for url, name in lists:
            th = FetchThread(url, FILTER_DIR / name)
            th.done.connect(ok)
            th.failed.connect(lambda e: self.statusBar().showMessage("Filter update failed: " + e, 8000))
            self.run_thread(th)
        self.statusBar().showMessage("Downloading filter lists…", 5000)

    # ================================================================ tabs
    def cur(self):
        return self.tabs.currentWidget()

    def play(self, name):
        if SETTINGS["sounds"] and name in self.sfx:
            self.sfx[name].play()

    def speed_dial(self):
        acc, bg = theme()
        tiles = "".join(f'<a href="{u}"><div class="t" style="background:{BRAND.get(s, "#2a2a38")}">{s}</div>{htmllib.escape(n)}</a>'
                        for s, n, u, _ in self.SIDEBAR)
        wp = SETTINGS["wallpaper"]
        is_video = wp.lower().endswith((".webm", ".mp4"))
        bgcss = (f"url('{wp}') center/cover fixed" if wp and not is_video and (DATA / wp).exists() else bg)
        page = (SPEED_HTML.replace("__BG__", bgcss).replace("__ACC__", acc)
                .replace("__ACTION__", search_url().split("?")[0]).replace("__TILES__", tiles)
                .replace("__STATS__", f"{SHIELDS.count} trackers & ads blocked this session"))
        if is_video and (DATA / wp).exists():   # live wallpaper
            page = page.replace("</body>", f'<video autoplay muted loop playsinline src="{wp}" style="position:fixed;'
                                'inset:0;width:100%;height:100%;object-fit:cover;z-index:-1"></video></body>')
        return page

    def go_home(self):
        self.cur().setHtml(self.speed_dial(), NEWTAB_BASE)

    def new_tab(self, url=None, html=None, raw=False):
        tab = Tab(self, self.profile)
        page = tab.page()
        tab.titleChanged.connect(lambda _t, tb=tab: self.update_tab_text(tb))
        tab.iconChanged.connect(lambda ic, tb=tab: self.tabs.setTabIcon(self.tabs.indexOf(tb), ic))
        tab.urlChanged.connect(lambda u, tb=tab: self.on_url_changed(tb, u))
        page.recentlyAudibleChanged.connect(lambda _a, tb=tab: self.update_tab_text(tb))
        page.fullScreenRequested.connect(self.on_fullscreen)
        page.linkHovered.connect(lambda u: self.statusBar().showMessage(u))
        page.newWindowRequested.connect(lambda req, tb=tab: self.on_new_window(req, tb))
        page.proxyAuthenticationRequired.connect(self.on_proxy_auth)
        page.certificateError.connect(self.on_cert_error)
        if hasattr(page, "permissionRequested"):
            page.permissionRequested.connect(self.on_permission)
        else:
            page.featurePermissionRequested.connect(lambda o, f, p=page: self.on_feature(p, o, f))
        i = self.tabs.addTab(tab, "New Tab")
        self.tabs.setCurrentIndex(i)
        self.play("open")
        if raw:
            return tab
        if url:
            tab.setUrl(QUrl(url))
        elif html:
            tab.setHtml(html, QUrl("about:blank"))
        else:
            tab.setHtml(self.speed_dial(), NEWTAB_BASE)
        return tab

    def update_tab_text(self, tab):
        i = self.tabs.indexOf(tab)
        if i < 0:
            return
        title = tab.title() if tab.title() and not tab.title().startswith("data:") else "New Tab"
        pre = ("📌" if tab.pinned else "") + ("🔊" if tab.page().recentlyAudible() else "")
        self.tabs.setTabText(i, (pre + " " if pre else "") + title[:28])
        if not self.ephemeral and self.history and self.history[-1]["url"] == tab.url().toString() and title != "New Tab":
            self.history[-1]["title"] = title
        if tab is self.cur():
            suffix = " — Tor" if self.tor else " — Private" if self.private else ""
            self.setWindowTitle(f"{title} — Nova{suffix}")

    def close_tab(self, i):
        w = self.tabs.widget(i)
        if not self.ephemeral and w.url().scheme() in ("http", "https"):
            self.closed.append(w.url().toString())
        if self.tabs.count() <= 1:
            self.close(); return
        self.tabs.removeTab(i); w.deleteLater()
        self.play("close")

    def reopen_tab(self):
        if self.closed:
            self.new_tab(self.closed.pop())

    def tab_menu(self, pos):
        i = self.tabs.tabBar().tabAt(pos)
        if i < 0:
            return
        t = self.tabs.widget(i)
        m = QMenu(self)
        self.act(m, "Unpin tab" if t.pinned else "Pin tab", lambda: self.toggle_pin(t))
        muted = t.page().isAudioMuted()
        self.act(m, "Unmute tab" if muted else "Mute tab", lambda: t.page().setAudioMuted(not muted))
        self.act(m, "Duplicate", lambda: self.new_tab(t.url().toString()))
        self.act(m, "Sleep tab", lambda: self.sleep_tab(t))
        self.act(m, "Close other tabs", lambda: self.close_others(t))
        if t.island is not None:
            self.act(m, "Remove from island", lambda: self.ungroup(t))
            self.act(m, "Close this island", lambda: self.close_island(t))
        m.exec(self.tabs.tabBar().mapToGlobal(pos))

    def toggle_pin(self, t):
        t.pinned = not t.pinned
        bar = self.tabs.tabBar()
        if t.pinned:
            self.tabs.moveTab(self.tabs.indexOf(t), 0)
            self.refresh_islands()
        self.tabs.setTabsClosable(False); self.tabs.setTabsClosable(True)
        for j in range(self.tabs.count()):
            if self.tabs.widget(j).pinned:
                bar.setTabButton(j, QTabBar.ButtonPosition.RightSide, None)
            self.update_tab_text(self.tabs.widget(j))

    def close_others(self, keep):
        for j in reversed(range(self.tabs.count())):
            w = self.tabs.widget(j)
            if w is not keep and not w.pinned:
                self.tabs.removeTab(j); w.deleteLater()

    def on_url_changed(self, tab, url):
        if tab is self.cur():
            self.urlbar.setText("" if is_blank(url) else url.toString())
            self.update_site_shield()
            z = SETTINGS["zoom"].get(url.host().lower())
            if z and abs(tab.zoomFactor() - z) > 0.01:
                tab.setZoomFactor(z)
            if SETTINGS["gsb"] and not self.tor and url.scheme() in ("http", "https"):
                self.safe_browsing_check(tab, url.toString())
        if not self.ephemeral and url.scheme() in ("http", "https"):
            self.history.append({"url": url.toString(), "t": int(time.time())})
            self.history = self.history[-5000:]

    def on_tab_changed(self, i):
        tab = self.cur()
        if not tab:
            return
        tab.last_active = time.time()
        tab.page().setLifecycleState(QWebEnginePage.LifecycleState.Active)
        self.urlbar.setText("" if is_blank(tab.url()) else tab.url().toString())
        self.update_site_shield()
        self.update_tab_text(tab)
        self.play("click")

    def navigate(self):
        text = self.urlbar.text().strip()
        if not text:
            return
        low = text.lower().replace(" ", "")
        if low.startswith(("javascript:", "vbscript:", "data:text/html", "data:application")):
            self.statusBar().showMessage("Blocked: pasting scripts into the address bar is a common scam", 8000)
            return
        if text.lower().startswith(("ipfs://", "ipns://")):
            text = self.ipfs_url(text)
        if " " in text or ("." not in text and "://" not in text and not text.startswith("localhost")):
            url = QUrl(search_url() + quote(text))
        else:
            url = QUrl.fromUserInput(text)
        self.cur().setUrl(url)

    def toggle_mute(self):
        p = self.cur().page()
        p.setAudioMuted(not p.isAudioMuted())
        self.statusBar().showMessage("Tab muted" if p.isAudioMuted() else "Tab unmuted", 3000)

    # ================================================================ page tools
    def zoom(self, d):
        v = self.cur()
        v.setZoomFactor(1.0 if d == 0 else max(0.25, min(5.0, v.zoomFactor() + d)))
        host = v.url().host().lower()
        if host:
            if abs(v.zoomFactor() - 1.0) < 0.01:
                SETTINGS["zoom"].pop(host, None)
            else:
                SETTINGS["zoom"][host] = round(v.zoomFactor(), 2)
            save_settings()

    def reader_mode(self):
        self.cur().page().runJavaScript(READER_JS.replace("__ACC__", theme()[0]))

    def print_pdf(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save as PDF", str(Path.home() / "page.pdf"), "PDF (*.pdf)")
        if p:
            self.cur().page().printToPdf(p)

    def screenshot(self):
        SHOT_DIR.mkdir(parents=True, exist_ok=True)
        p = SHOT_DIR / time.strftime("nova_%Y%m%d_%H%M%S.png")
        self.cur().grab().save(str(p))
        self.statusBar().showMessage(f"Screenshot saved: {p}", 8000)

    def open_devtools(self):
        dev = QWebEnginePage(self.profile, self)
        self.cur().page().setDevToolsPage(dev)
        v = QWebEngineView(); v.setPage(dev); v.resize(1000, 650); v.setWindowTitle("DevTools — Nova")
        v.show(); self._dev.append(v)

    def on_fullscreen(self, request):
        request.accept()
        self.showFullScreen() if request.toggleOn() else self.showNormal()

    def perm_ask(self, host, kind):
        saved = SETTINGS["site_perms"].get(host, {}).get(kind)
        if saved is not None:
            return saved
        box = QMessageBox(self)
        box.setWindowTitle("Permission request")
        box.setText(f"{host} wants access: {kind}")
        allow = box.addButton("Allow", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Block", QMessageBox.ButtonRole.RejectRole)
        cb = QCheckBox("Remember for this site")
        box.setCheckBox(cb)
        box.exec()
        ok = box.clickedButton() is allow
        if cb.isChecked():
            SETTINGS["site_perms"].setdefault(host, {})[kind] = ok
            save_settings()
        return ok

    def on_permission(self, perm):
        try:
            kind = perm.permissionType().name
        except Exception:
            kind = str(perm.permissionType())
        ok = (not self.tor) and self.perm_ask(perm.origin().host(), kind)
        perm.grant() if ok else perm.deny()

    def on_feature(self, page, origin, feat):
        P = QWebEnginePage.PermissionPolicy
        ok = (not self.tor) and self.perm_ask(origin.host(), feat.name)
        page.setFeaturePermission(origin, feat, P.PermissionGrantedByUser if ok else P.PermissionDeniedByUser)

    def on_download(self, item):
        d = Path.home() / "Downloads"
        d.mkdir(exist_ok=True)
        ext = Path(item.downloadFileName() or item.url().fileName()).suffix.lower()
        if SETTINGS["dl_warn"] and ext in DANGEROUS_EXT:
            r = QMessageBox.warning(self, "Risky download",
                                    f"{item.downloadFileName()} ({ext}) can run code on your computer.\n"
                                    f"From: {item.url().host()}\n\nDownload anyway?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                item.cancel()
                return
        item.setDownloadDirectory(str(d))
        item.accept()
        item.isFinishedChanged.connect(lambda it=item: self.on_download_done(it, d))

    # ================================================================ performance
    def is_discarded(self, t):
        return t.page().lifecycleState() == QWebEnginePage.LifecycleState.Discarded

    def sleep_tab(self, t):
        if t is not self.cur() and not t.page().recentlyAudible():
            t.page().setLifecycleState(QWebEnginePage.LifecycleState.Discarded)

    def sleep_background(self):
        for i in range(self.tabs.count()):
            self.sleep_tab(self.tabs.widget(i))

    def app_stats(self):
        me = psutil.Process()
        mem = cpu = 0.0
        alive = set()
        for p in [me] + me.children(recursive=True):
            try:
                pp = self._procs.setdefault(p.pid, p)
                mem += pp.memory_info().rss
                cpu += pp.cpu_percent(None)
                alive.add(p.pid)
            except psutil.Error:
                pass
        for k in list(self._procs):
            if k not in alive:
                del self._procs[k]
        return mem / 1048576, cpu / (psutil.cpu_count() or 1)

    def resource_tick(self):
        S = SETTINGS
        mem, cpu = self.app_stats()
        self.ram_label.setText(f"Browser RAM: {mem:.0f} MB")
        self.cpu_label.setText(f"Browser CPU: {cpu:.0f}%")
        if S["ram_limit"] and mem > S["ram_mb"]:
            self.sleep_background()
        if S["cpu_limit"] and cpu > S["cpu_pct"]:
            self.sleep_background()
        now, cur = time.time(), self.cur()
        if cur:
            cur.last_active = now
        tabs = [self.tabs.widget(i) for i in range(self.tabs.count())]
        if S["tab_limit"]:
            awake = sorted((t for t in tabs if t is not cur and not self.is_discarded(t)),
                           key=lambda t: t.last_active)
            for t in awake[:max(0, len(awake) + 1 - S["tab_max"])]:
                self.sleep_tab(t)
        if S["autosleep"]:
            for t in tabs:
                if now - t.last_active > S["autosleep_min"] * 60:
                    self.sleep_tab(t)
        if S["low_priority"]:
            for pp in list(self._procs.values()):
                try:
                    pp.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if sys.platform == "win32" else 10)
                except (psutil.Error, AttributeError):
                    pass

    def clean(self):
        self.profile.clearHttpCache()
        self.profile.cookieStore().deleteAllCookies()
        self.history.clear()
        save_json(HISTORY_FILE, [])
        self.closed.clear()
        QMessageBox.information(self, "Cleaner", "Cache, cookies, history and closed-tab list cleared.")

    # ================================================================ bookmarks / history / workspaces / session
    def add_bookmark(self):
        t = self.cur()
        u = t.url().toString()
        if t.url().scheme() not in ("http", "https"):
            return
        if any(b["url"] == u for b in self.bookmarks):
            self.bookmarks = [b for b in self.bookmarks if b["url"] != u]
            self.statusBar().showMessage("Bookmark removed", 3000)
        else:
            self.bookmarks.append({"title": t.title(), "url": u})
            self.statusBar().showMessage("Bookmarked", 3000)
        save_json(BOOKMARKS_FILE, self.bookmarks)
        self.update_site_shield()

    def fill_bookmarks(self, m):
        self.act(m, "★ Bookmark this page", self.add_bookmark)
        m.addSeparator()
        for b in self.bookmarks[-60:]:
            self.act(m, (b["title"] or b["url"])[:55], lambda u=b["url"]: self.cur().setUrl(QUrl(u)))

    def fill_history(self, m):
        for h in reversed(self.history[-25:]):
            self.act(m, h["url"][:70], lambda u=h["url"]: self.cur().setUrl(QUrl(u)))
        if self.history:
            m.addSeparator()
            self.act(m, "Clear history", lambda: (self.history.clear(), save_json(HISTORY_FILE, [])))
        else:
            m.addAction("(empty)").setEnabled(False)

    def fill_workspaces(self, m):
        self.act(m, "Save current tabs as workspace…", self.save_workspace)
        m.addSeparator()
        for name in load_json(WORKSPACES_FILE, {}):
            self.act(m, name, lambda n=name: self.open_workspace(n))

    def open_urls(self):
        return [self.tabs.widget(i).url().toString() for i in range(self.tabs.count())
                if self.tabs.widget(i).url().scheme() in ("http", "https")]

    def save_workspace(self):
        name, ok = QInputDialog.getText(self, "Workspace", "Workspace name:")
        if ok and name.strip():
            ws = load_json(WORKSPACES_FILE, {})
            ws[name.strip()] = self.open_urls()
            save_json(WORKSPACES_FILE, ws)

    def open_workspace(self, name):
        for u in load_json(WORKSPACES_FILE, {}).get(name, []):
            self.new_tab(u)

    def restore_session(self):
        for u in load_json(SESSION_FILE, []):
            self.new_tab(u)

    def export_bookmarks(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export bookmarks", "nova_bookmarks.json", "JSON (*.json)")
        if p:
            save_json(p, self.bookmarks)

    def import_bookmarks(self):
        p, _ = QFileDialog.getOpenFileName(self, "Import bookmarks", "", "JSON (*.json)")
        if p:
            data = load_json(p, [])
            known = {b["url"] for b in self.bookmarks}
            self.bookmarks += [b for b in data if isinstance(b, dict) and b.get("url") and b["url"] not in known]
            save_json(BOOKMARKS_FILE, self.bookmarks)

    # ================================================================ GX Corner / updates / about
    def gx_corner(self):
        if self.net_blocked():
            return
        th = FetchThread("https://www.cheapshark.com/api/1.0/deals?pageSize=24&sortBy=Savings&onSale=1&upperPrice=30",
                         DATA / "deals.json")
        th.done.connect(self.show_deals)
        th.failed.connect(lambda e: self.statusBar().showMessage("GX Corner: " + e, 8000))
        self.run_thread(th)

    def show_deals(self, path):
        acc, bg = theme()
        cards = ""
        for d in load_json(path, [])[:24]:
            title = htmllib.escape(str(d.get("title", "?")))
            try:
                save = f"-{float(d.get('savings', 0)):.0f}%"
            except ValueError:
                save = ""
            cards += (f'<a class="c" href="https://www.cheapshark.com/redirect?dealID={quote(str(d.get("dealID", "")))}">'
                      f'<img src="{htmllib.escape(str(d.get("thumb", "")))}"><b>{title}</b>'
                      f'<span>${htmllib.escape(str(d.get("salePrice", "")))} <s>${htmllib.escape(str(d.get("normalPrice", "")))}</s> '
                      f'<em>{save}</em></span></a>')
        page = (f"<html><body style='background:{bg};color:#eee;font-family:Segoe UI;padding:30px'>"
                f"<h1 style='color:{acc}'>🎮 GX Corner — game deals</h1><p style='color:#999'>Data: CheapShark</p>"
                "<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:16px'>"
                f"{cards}</div><style>.c{{background:#1d1d28;border-radius:10px;padding:10px;color:#eee;text-decoration:none;"
                f"display:flex;flex-direction:column;gap:6px}}.c:hover{{outline:2px solid {acc}}}img{{width:100%;border-radius:6px}}"
                f"em{{color:{acc};font-style:normal;font-weight:bold}}s{{color:#888}}</style></body></html>")
        self.new_tab(html=page)

    def check_updates(self, manual=False):
        if self.tor or self.private or (not manual and not SETTINGS["auto_update"]):
            return
        url = SETTINGS["update_url"].strip() or DEFAULT_UPDATE_URL
        if not url:
            if manual:
                QMessageBox.information(self, "Updates", "Set an update manifest URL in ⚙ → Advanced (see README.md).")
            return
        th = FetchThread(url, DATA / "update.json")
        th.done.connect(lambda p: self.on_manifest(p, manual))
        th.failed.connect(lambda e: QMessageBox.warning(self, "Updates", e) if manual else None)
        self.run_thread(th)

    def on_manifest(self, path, manual):
        try:
            m = json.loads(Path(path).read_text(encoding="utf-8"))
            newv = str(m["version"])
        except Exception as e:
            if manual:
                QMessageBox.warning(self, "Updates", f"Bad manifest: {e}")
            return
        if vtuple(newv) <= vtuple(VERSION):
            if manual:
                QMessageBox.information(self, "Updates", f"You're up to date (v{VERSION}).")
            return
        if not self.verify_manifest(m):
            QMessageBox.warning(self, "Updates", "The update's signature is invalid, or no update public key is set "
                                "(⚙ → Advanced). Refusing to install.")
            return
        notes = m.get("notes", "")
        if QMessageBox.question(self, "Update available",
                                f"Nova {newv} is available (you have {VERSION}).\n\n{notes}\n\nInstall now?"
                                ) != QMessageBox.StandardButton.Yes:
            return
        url, sha = str(m.get("url", "")), str(m.get("sha256", ""))
        if not url.startswith("https://") or len(sha) != 64:
            QMessageBox.warning(self, "Updates", "Manifest must contain an https URL and a sha256 hash. Refusing.")
            return
        self._pending_sha = sha
        th = FetchThread(url, Path(tempfile.gettempdir()) / f"NovaSetup-{newv}.exe", sha)
        th.done.connect(self.run_installer)
        th.failed.connect(lambda e: QMessageBox.warning(self, "Updates", "Download failed: " + e))
        self.run_thread(th)
        self.statusBar().showMessage("Downloading update…", 10000)

    def run_installer(self, path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest().lower() != getattr(self, "_pending_sha", "x").lower():
            Path(path).unlink(missing_ok=True)        # re-verify right before running (file could have been swapped)
            QMessageBox.critical(self, "Updates", "The update file changed after download. It was deleted.")
            return
        if sys.platform != "win32":
            QMessageBox.information(self, "Updates", f"Downloaded to {path}"); return
        subprocess.Popen([path, "/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"])
        QApplication.quit()

    def make_default(self):
        if sys.platform == "win32":
            os.startfile("ms-settings:defaultapps")
        else:
            self.statusBar().showMessage("Set the default browser in your system settings", 6000)

    def about(self):
        QMessageBox.about(self, "Nova Browser", f"<b>Nova Browser {VERSION}</b><br>Chromium engine via QtWebEngine."
                          f"<br>Data folder: {DATA}")

    # ================================================================ private / Tor
    def open_private(self):
        w = Browser(private=True); w.show()
        PRIVATE_WINDOWS.append(w)

    def open_tor(self):
        cmd = ([sys.executable, "--tor"] if IS_FROZEN
               else [sys.executable, str(Path(__file__).resolve()), "--tor"])
        subprocess.Popen(cmd)

    def start_tor(self):
        self.urlbar.setEnabled(False)
        self.tor_label.setText("🧅 connecting…")
        self.new_tab(html=TOR_WAIT_HTML)
        if not self.tor_exe:
            self.on_tor_ready()
        else:
            self.launch_tor()

    def launch_tor(self):
        DATA_TOR.mkdir(exist_ok=True)
        args = ["--SocksPort", f"127.0.0.1:{TOR_PORT_OWN} IsolateDestAddr", "--DataDirectory", str(DATA_TOR),
                "--ClientOnly", "1", "--SafeSocks", "1"]
        bridges = [b.strip() for b in SETTINGS["tor_bridges"].splitlines() if b.strip() and not b.strip().startswith("#")]
        if bridges:
            pt = None
            for base in (self.tor_exe.parent / "pluggable_transports", self.tor_exe.parent.parent / "pluggable_transports"):
                for n in ("lyrebird.exe", "lyrebird", "obfs4proxy.exe", "obfs4proxy"):
                    if (base / n).is_file():
                        pt = base / n
            args += ["--UseBridges", "1"]
            if pt:
                args += ["--ClientTransportPlugin", f'obfs4 exec "{pt}"']
            for b in bridges:
                args += ["--Bridge", b[7:] if b.lower().startswith("bridge ") else b]
        for d in (self.tor_exe.parent / "data", self.tor_exe.parent.parent / "data"):
            if (d / "geoip").exists():
                args += ["--GeoIPFile", str(d / "geoip"), "--GeoIPv6File", str(d / "geoip6")]
                break
        self.tor_done = False
        self.tor_proc = QProcess(self)
        self.tor_proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.tor_proc.readyReadStandardOutput.connect(self.on_tor_output)
        self.tor_proc.errorOccurred.connect(lambda _: self.tor_label.setText("🧅 Tor failed to start"))
        self.tor_proc.start(str(self.tor_exe), args)

    def on_tor_output(self):
        out = bytes(self.tor_proc.readAllStandardOutput()).decode(errors="ignore")
        for pct in re.findall(r"Bootstrapped (\d+)%", out):
            self.tor_label.setText(f"🧅 {pct}%")
            if int(pct) >= 100 and not self.tor_done:
                self.tor_done = True
                self.on_tor_ready()

    def on_tor_ready(self):
        self.urlbar.setEnabled(True)
        self.tor_label.setText("🧅 Tor connected")
        self.cur().setUrl(QUrl("https://check.torproject.org"))

    def new_identity(self):
        self.profile.cookieStore().deleteAllCookies()
        self.profile.clearHttpCache()
        if self.tor_proc:
            self.tor_proc.kill(); self.tor_proc.waitForFinished(3000)
            self.urlbar.setEnabled(False)
            self.tor_label.setText("🧅 new identity…")
            self.cur().setHtml(TOR_WAIT_HTML, QUrl("about:blank"))
            self.launch_tor()
        else:
            self.cur().reload()


    # ================================================================ security / privacy extras
    def js_allowed(self, host):
        host = (host or "").lower()
        if self.tor and SETTINGS["tor_level"] == "Safest":
            return False
        return not (host and host_in(host, set(SETTINGS["js_off_hosts"])))

    def toggle_js(self):
        host = self.cur().url().host().lower()
        if not host:
            return
        off = set(SETTINGS["js_off_hosts"])
        off.symmetric_difference_update({host})
        SETTINGS["js_off_hosts"] = sorted(off)
        save_settings()
        self.cur().reload()
        self.update_site_shield()

    def on_new_window(self, req, parent=None):
        if SETTINGS["popup_block"] and not req.isUserInitiated():
            self.statusBar().showMessage("Popup blocked: " + req.requestedUrl().host(), 6000)
            return
        tab = self.new_tab(raw=True)
        self.join_island(parent, tab)
        req.openIn(tab.page())

    def float_video(self):
        tab = self.cur()

        def go(ok):
            if not ok:
                self.statusBar().showMessage("No playing video found on this page", 5000)
                return
            if self.tabs.count() == 1:
                self.new_tab()
            self.tabs.removeTab(self.tabs.indexOf(tab))
            fw = FloatWindow(tab, self)
            self._floats.append(fw)
            fw.show()
        tab.page().runJavaScript(FLOAT_ON_JS, go)

    def ipfs_url(self, text):
        kind, rest = text.split("://", 1)
        if port_open(8080):
            return f"http://127.0.0.1:8080/{kind}/{rest}"
        self.statusBar().showMessage("No local IPFS node found — using the public dweb.link gateway", 8000)
        return f"https://dweb.link/{kind}/{rest}"

    def apply_preset(self, name):
        SETTINGS.update(PRESETS[name])
        save_settings()
        self.apply_scripts()
        self.panel.setWidget(self.panel_content())
        self.statusBar().showMessage(f"Preset '{name}' applied (paranoid mode / DoH need a restart)", 10000)

    def fill_tests(self, m):
        for name, url in (("EFF Cover Your Tracks", "https://coveryourtracks.eff.org"),
                          ("BrowserLeaks", "https://browserleaks.com"),
                          ("IP / DNS / WebRTC leak test", "https://ipleak.net"),
                          ("Tor check", "https://check.torproject.org")):
            self.act(m, name, lambda u=url: self.new_tab(u))

    def _ask_pw(self, title, confirm=False):
        pw, ok = QInputDialog.getText(self, title, "Passphrase (8+ characters):", QLineEdit.EchoMode.Password)
        if not ok:
            return None
        if len(pw) < 8:
            QMessageBox.warning(self, title, "Use at least 8 characters.")
            return None
        if confirm:
            pw2, ok = QInputDialog.getText(self, title, "Repeat passphrase:", QLineEdit.EchoMode.Password)
            if not ok or pw2 != pw:
                QMessageBox.warning(self, title, "Passphrases don't match.")
                return None
        return pw

    def set_master_password(self):
        global KEY
        if not HAVE_CRYPTO:
            QMessageBox.warning(self, "Nova", "Install the 'cryptography' package first.")
            return
        pw = self._ask_pw("New master password (cannot be recovered!)", True)
        if not pw:
            return
        data = {n: load_json(DATA / n, d) for n, d in SECURE_DEFAULTS.items() if (DATA / n).exists()}
        salt = os.urandom(16)
        (DATA / "lock.salt").write_bytes(salt)
        KEY = derive_key(pw, salt)
        nonce = os.urandom(12)
        (DATA / "lock.check").write_bytes(nonce + AESGCM(KEY).encrypt(nonce, b"nova-ok", None))
        for n, d in data.items():
            save_json(DATA / n, d)
        SETTINGS["app_lock"] = True
        save_settings()
        QMessageBox.information(self, "Nova", "Master password set. Bookmarks, history, session, workspaces and "
                                "the vault are now encrypted on disk. Nova will ask for it at startup.")

    def open_vault(self):
        if KEY is None:
            self.set_master_password()
        if KEY is not None:
            VaultDialog(self).exec()

    def export_backup(self):
        if not HAVE_CRYPTO:
            QMessageBox.warning(self, "Backup", "Install the 'cryptography' package first.")
            return
        pw = self._ask_pw("Backup passphrase", True)
        if not pw:
            return
        p, _ = QFileDialog.getSaveFileName(self, "Encrypted backup", "nova_backup.nvb", "Nova backup (*.nvb)")
        if not p:
            return
        salt, nonce = os.urandom(16), os.urandom(12)
        payload = json.dumps({"bookmarks": self.bookmarks, "workspaces": load_json(WORKSPACES_FILE, {}),
                              "vault": load_json(VAULT_FILE, {})}).encode()
        Path(p).write_bytes(b"NVB1" + salt + nonce + AESGCM(derive_key(pw, salt)).encrypt(nonce, payload, None))
        self.statusBar().showMessage("Encrypted backup written — safe to put in any cloud folder", 8000)

    def import_backup(self):
        p, _ = QFileDialog.getOpenFileName(self, "Import encrypted backup", "", "Nova backup (*.nvb)")
        if not p:
            return
        raw = Path(p).read_bytes()
        if not raw.startswith(b"NVB1"):
            QMessageBox.warning(self, "Backup", "Not a Nova backup file.")
            return
        pw = self._ask_pw("Backup passphrase")
        if not pw:
            return
        try:
            data = json.loads(AESGCM(derive_key(pw, raw[4:20])).decrypt(raw[20:32], raw[32:], None))
        except Exception:
            QMessageBox.warning(self, "Backup", "Wrong passphrase or corrupted file.")
            return
        known = {b["url"] for b in self.bookmarks}
        self.bookmarks += [b for b in data.get("bookmarks", []) if b.get("url") and b["url"] not in known]
        save_json(BOOKMARKS_FILE, self.bookmarks)
        ws = load_json(WORKSPACES_FILE, {})
        ws.update(data.get("workspaces", {}))
        save_json(WORKSPACES_FILE, ws)
        vault, note = data.get("vault", {}), ""
        if vault.get("entries") or vault.get("api_key"):
            if KEY is None:
                note = "\nVault entries were skipped — set a master password first, then import again."
            else:
                v = load_json(VAULT_FILE, {})
                v.setdefault("entries", [])
                seen = {(e["site"], e["user"]) for e in v["entries"]}
                v["entries"] += [e for e in vault.get("entries", []) if (e["site"], e["user"]) not in seen]
                if vault.get("api_key") and not v.get("api_key"):
                    v["api_key"] = vault["api_key"]
                save_json(VAULT_FILE, v)
        QMessageBox.information(self, "Backup", "Backup imported." + note)

    # ================================================================ library / productivity / safety
    def all_tabs(self):
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def open_library(self, index=0):
        LibraryDialog(self, index).exec()
        self.update_site_shield()

    def pin_page(self):
        t = self.cur()
        if t.url().scheme() not in ("http", "https"):
            return
        pins = load_json(PIN_FILE, {})
        board, ok = QInputDialog.getItem(self, "Pinboard", "Pin to board (type a new name to create one):",
                                         list(pins) or ["Reading list"], 0, True)
        if ok and board.strip():
            pins.setdefault(board.strip(), []).append({"title": t.title(), "url": t.url().toString()})
            save_json(PIN_FILE, pins)
            self.statusBar().showMessage(f"Pinned to {board.strip()}", 4000)

    def flow_add(self, text=None, kind="note"):
        if text is None:
            text, ok = QInputDialog.getMultiLineText(self, "Flow", "Note or link:")
            if not ok:
                return
        text = (text or "").strip()
        if text:
            items = load_json(FLOW_FILE, [])
            items.append({"t": int(time.time()), "kind": "link" if text.startswith("http") else kind, "text": text})
            save_json(FLOW_FILE, items[-300:])
            self.statusBar().showMessage("Saved to Flow", 4000)

    def flow_open(self, x):
        if x and x["text"].startswith("http"):
            self.new_tab(x["text"])
        elif x:
            QApplication.clipboard().setText(x["text"])
            self.statusBar().showMessage("Copied to clipboard", 3000)

    def tab_search(self):
        entries = []
        for i, t in enumerate(self.all_tabs()):
            entries.append((f"{t.title() or 'New Tab'}  —  {t.url().toString()[:80]}",
                            lambda i=i: self.tabs.setCurrentIndex(i)))
        for u in reversed(self.closed[-15:]):
            entries.append((f"↺ Reopen:  {u[:90]}", lambda u=u: self.new_tab(u)))
        QuickPicker(self, "Search tabs", entries, "Search open tabs…").exec()

    def command_palette(self):
        C = [("New tab", lambda: self.new_tab()), ("New private window", self.open_private),
             ("New Tor window", self.open_tor), ("Bookmarks manager", lambda: self.open_library(0)),
             ("History", lambda: self.open_library(1)), ("Pinboards", lambda: self.open_library(2)),
             ("Flow — notes & links", lambda: self.open_library(3)), ("Downloads manager", lambda: self.open_library(4)),
             ("Site permissions", lambda: self.open_library(5)), ("Pin this page", self.pin_page),
             ("Send this page to Flow", lambda: self.flow_add(self.cur().url().toString(), "link")),
             ("Search tabs", self.tab_search), ("Settings", lambda: self.toggle(self.panel)),
             ("VPN", lambda: self.toggle(self.vpn)), ("Extensions", self.open_extensions),
             ("Sidebar apps", self.open_sidebar_apps), ("Translate this page", self.translate_page),
             ("Reader mode", self.reader_mode), ("Screenshot", self.screenshot), ("View page source", self.view_source),
             ("Save page as…", self.save_page), ("Print / save as PDF", self.print_pdf),
             ("Floating video", self.float_video), ("Security checkup", self.security_checkup),
             ("Autofill: addresses & cards", self.open_autofill), ("Vault — passwords", self.open_vault),
             ("Scan a file with antivirus", self.scan_pick_file), ("Cleaner — clear cache & cookies", self.clean),
             ("Show / hide bookmarks bar", self.toggle_bookmarks_bar), ("PANIC WIPE", lambda: self.panic(True))]
        QuickPicker(self, "Command palette", C, "Type a command…").exec()

    def toggle_bookmarks_bar(self):
        SETTINGS["bookmarks_bar"] = not SETTINGS["bookmarks_bar"]
        save_settings()
        self.refresh_bookmarks_bar(True)

    def refresh_bookmarks_bar(self, force=False):
        sig = (SETTINGS["bookmarks_bar"], len(self.bookmarks)) + tuple(b["url"] for b in self.bookmarks[:24])
        if not force and sig == getattr(self, "_bm_sig", None):
            return
        self._bm_sig = sig
        self.bm_bar.clear()
        self.bm_bar.setVisible(bool(SETTINGS["bookmarks_bar"]) and not self.tor)
        for b in self.bookmarks[:24]:
            label = (b.get("title") or b["url"]).replace("&", "&&")
            a = self.act(self.bm_bar, label if len(label) <= 22 else label[:21] + "…",
                         lambda u=b["url"]: self.cur().setUrl(QUrl(u)))
            a.setIcon(svg_icon("star", "#8a8a99", 14))
            a.setToolTip(b["url"])
        self.act(self.bm_bar, "Manage…", lambda: self.open_library(0))

    def update_suggestions(self, text):
        q = text.strip().lower()
        out, seen = [], set()
        if len(q) >= 2 and not self.tor:
            for src in (self.bookmarks[::-1], self.history[::-1]):
                for it in src:
                    u = it["url"]
                    if u not in seen and (q in u.lower() or q in (it.get("title") or "").lower()):
                        seen.add(u)
                        out.append(u)
                        if len(out) >= 8:
                            break
                if len(out) >= 8:
                    break
        self.sugg_model.setStringList(out)

    # ---- tab islands ----
    def join_island(self, parent, child):
        if parent is None or parent is child:
            return
        if parent.island is None:
            self._island_seq += 1
            parent.island = self._island_seq
        child.island = parent.island
        others = [self.tabs.indexOf(t) for t in self.all_tabs() if t.island == parent.island and t is not child]
        ci = self.tabs.indexOf(child)
        if others and ci > max(others) + 1:
            self.tabs.moveTab(ci, max(others) + 1)
        self.refresh_islands()

    def refresh_islands(self):
        bar = self.tabs.bar
        for i, t in enumerate(self.all_tabs()):
            if t.island is None:
                bar.setTabButton(i, QTabBar.ButtonPosition.LeftSide, None)
            else:
                dot = QLabel()
                dot.setFixedSize(9, 9)
                dot.setStyleSheet(f"background:{ISLAND_COLORS[t.island % len(ISLAND_COLORS)]};border-radius:4px;")
                bar.setTabButton(i, QTabBar.ButtonPosition.LeftSide, dot)

    def ungroup(self, t):
        t.island = None
        self.refresh_islands()

    def close_island(self, t):
        if t.island is None:
            return
        for tab in [x for x in self.all_tabs() if x.island == t.island]:
            self.close_tab(self.tabs.indexOf(tab))

    # ---- Easy Files ----
    def easy_files(self, multiple):
        cands = [d["path"] for d in reversed(self.dl_items)]
        for folder in (Path.home() / "Downloads", SHOT_DIR):
            try:
                cands += [str(p) for p in sorted(folder.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True)[:15]
                          if p.is_file()]
            except OSError:
                pass
        files, seen = [], set()
        for c in cands:
            if c not in seen and Path(c).is_file():
                seen.add(c)
                files.append(c)
        if not files:
            fs, _ = (QFileDialog.getOpenFileNames(self, "Choose files") if multiple
                     else ([QFileDialog.getOpenFileName(self, "Choose a file")[0]], None))
            return [f for f in fs if f]
        dlg = EasyFilesDialog(self, files[:30], multiple)
        dlg.exec()
        return dlg.result_files

    # ---- autofill / translate / safe browsing ----
    def open_autofill(self):
        if KEY is None:
            self.set_master_password()
        if KEY is not None:
            AutofillDialog(self).exec()

    def fill_form(self, values):
        t = self.cur()
        if t.url().scheme() != "https":
            QMessageBox.warning(self, "Autofill", "Autofill only works on secure (HTTPS) pages.")
            return
        host = t.url().host()
        t.page().runJavaScript(FILL_JS.replace("__V__", json.dumps(values)),
                               lambda n: self.statusBar().showMessage(f"Filled {n or 0} field(s) on {host}", 6000))

    def translate_page(self):
        langs = {"English": "en", "Spanish": "es", "French": "fr", "German": "de", "Portuguese": "pt", "Italian": "it",
                 "Arabic": "ar", "Hindi": "hi", "Chinese (Simplified)": "zh-CN", "Japanese": "ja", "Korean": "ko",
                 "Russian": "ru", "Turkish": "tr", "Yoruba": "yo", "Swahili": "sw"}
        lang, ok = QInputDialog.getItem(self, "Translate", "Translate this page into:", list(langs), 0, False)
        if not ok:
            return
        how, ok = QInputDialog.getItem(self, "Translate", "Method:", [
            "Google Translate (sends the page address to Google)",
            "Claude (sends page text to Anthropic; needs your API key)"], 0, False)
        if not ok:
            return
        if how.startswith("Google"):
            self.new_tab("https://translate.google.com/translate?sl=auto&tl=" + langs[lang] + "&u="
                         + quote(self.cur().url().toString(), safe=""))
        else:
            self.assistant.show()
            self.assistant.send(False, f"Translate the main text of this page into {lang}. Keep it readable; "
                                       "summarise sections that are very long.")

    def safe_browsing_check(self, tab, url):
        if url in self._gsb_seen:
            return
        self._gsb_seen.add(url)
        key = self.get_secret("gsb_key", "Google Safe Browsing API key")
        if not key:
            SETTINGS["gsb"] = False
            save_settings()
            return
        th = GsbThread(key, url)
        th.flagged.connect(lambda u, kind, tb=tab: self.on_unsafe(tb, u, kind))
        self.run_thread(th)

    def on_unsafe(self, tab, url, kind):
        if tab.url().toString() == url:
            tab.setHtml(UNSAFE_HTML.replace("__KIND__", htmllib.escape(kind)).replace("__URL__", htmllib.escape(url)),
                        QUrl("about:blank"))

    # ---- Razer Chroma ----
    def start_chroma(self):
        self.chroma = ChromaLink()
        self.chroma.start()
        self.chroma_update()

    def toggle_chroma(self, on):
        if on and not self.chroma:
            self.start_chroma()
        elif not on and self.chroma:
            self.chroma.stop()
            self.chroma = None

    def chroma_update(self, color=None):
        if self.chroma:
            self.chroma.set_hex(color or ("#a855f7" if self.tor else "#22c55e" if active_vpn_url() else theme()[0]))

    # ---- extensions / sidebar apps / profiles ----
    def open_extensions(self):
        ExtensionsDialog(self).exec()

    def open_sidebar_apps(self):
        SidebarAppsDialog(self).exec()

    def view_source(self):
        u = self.cur().url().toString()
        if u.startswith(("http://", "https://")):
            self.new_tab("view-source:" + u)

    def save_page(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save page", str(Path.home() / "page.mhtml"), "Web page (*.mhtml)")
        if p:
            self.cur().page().save(p)
            self.statusBar().showMessage("Saving page…", 4000)

    def fill_profiles(self, m):
        self.act(m, "Default" + ("  ✓" if not PROFILE else ""), lambda: self.open_profile(""))
        for d in sorted((ROOT_DATA / "profiles").glob("*")):
            if d.is_dir():
                self.act(m, d.name + ("  ✓" if d.name == PROFILE else ""), lambda n=d.name: self.open_profile(n))
        m.addSeparator()
        self.act(m, "New profile…", self.new_profile)

    def open_profile(self, name):
        cmd = [sys.executable] if IS_FROZEN else [sys.executable, str(Path(__file__).resolve())]
        subprocess.Popen(cmd + (["--profile", name] if name else []))

    def new_profile(self):
        n, ok = QInputDialog.getText(self, "New profile", "Profile name (letters and numbers):")
        n = re.sub(r"[^A-Za-z0-9_-]", "", n)[:24] if ok else ""
        if n:
            (ROOT_DATA / "profiles" / n).mkdir(parents=True, exist_ok=True)
            self.open_profile(n)

    # ---- safety ----
    def on_cert_error(self, error):
        host = error.url().host()
        if error.isOverridable() and host in LOCAL_HOSTS:
            error.acceptCertificate()
        else:
            error.rejectCertificate()
            self.statusBar().showMessage(f"Blocked an insecure connection to {host}: {error.description()}", 12000)

    def security_checkup(self):
        good = lambda c, a, b: ("✔  " + a) if c else ("⚠  " + b)
        m = re.search(r"Chrome/([\d.]+)", self.profile.httpUserAgent())
        admin = False
        if sys.platform == "win32":
            try:
                admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                pass
        signed = bool((SETTINGS["update_pubkey"] or DEFAULT_UPDATE_PUBKEY) and (SETTINGS["update_url"] or DEFAULT_UPDATE_URL))
        lines = [
            good(not os.environ.get("QTWEBENGINE_DISABLE_SANDBOX"), "Chromium sandbox is on", "Sandbox is disabled!"),
            f"ℹ  Engine: Chromium {m.group(1) if m else '?'} (Qt {QT_VERSION_STR}) — install Nova updates promptly: "
            "engine security fixes arrive with new Qt releases",
            good(SETTINGS["shield"], "Shields are on", "Shields are off"),
            good(SETTINGS["https"], "HTTPS upgrade is on", "HTTPS upgrade is off"),
            good(SETTINGS["block_3p_cookies"], "Third-party cookies blocked", "Third-party cookies allowed"),
            good(SETTINGS["fingerprint"], "Fingerprinting protection is on", "Fingerprinting protection is off"),
            good(SETTINGS["popup_block"], "Popup blocker is on", "Popup blocker is off"),
            good(SETTINGS["dl_warn"], "Risky-download warnings are on", "Risky-download warnings are off"),
            good(SETTINGS["av_scan"], "Downloads are scanned", "Download scanning is off"),
            good(find_defender() is not None, "Microsoft Defender found", "Defender not found — only basic file checks"),
            good(KEY is not None, "Master password set — local data is encrypted",
                 "No master password — history, bookmarks and the vault are not encrypted"),
            good(signed, "Signed updates are configured", "Signed updates are not configured"),
            good(not admin, "Not running as administrator", "Running as administrator — use a normal account"),
            good(find_widevine() is not None, "Widevine (DRM) found", "Widevine not found — DRM video may not play"),
            good(SETTINGS["clear_on_exit"] or SETTINGS["paranoid"], "Browsing data is cleared on exit / paranoid mode",
                 "Browsing data is kept on disk (turn on Clear on exit for more privacy)"),
        ]
        QMessageBox.information(self, "Security checkup", "\n".join(lines))

    def media_page(self):
        for t in self.all_tabs():
            if t.page().recentlyAudible():
                return t.page()
        if self.side.view.page().recentlyAudible():
            return self.side.view.page()
        t = self.cur()
        return t.page() if t else None

    # ================================================================ panic wipe / antivirus / VPN
    def panic(self, confirm=False):
        """PANIC WIPE: hide windows, kill every Nova process (incl. Tor), then a detached helper securely
        deletes browsing data, cookies, cache, history, session, Tor state, optional downloads/screenshots."""
        if confirm and QMessageBox.question(
                self, "Panic Wipe", "Erase all browsing activity and close Nova immediately?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            for w in QApplication.topLevelWidgets():
                w.hide()
            job = Path(tempfile.gettempdir()) / f"nova_wipe_{os.getpid()}.json"
            for k in ("shields_off", "js_off_hosts", "site_perms", "zoom"):      # site lists reveal where you've been
                SETTINGS[k] = type(DEFAULTS[k])()
            save_settings()
            recent = [Path(x).name for x in load_json(DOWNLOADS_LOG, [])]
            job.write_text(json.dumps({"pid": os.getpid(), "paths": panic_targets(), "recent": recent,
                                       "scorched": bool(SETTINGS["panic_scorched"]),
                                       "freespace": str(Path.home()) if SETTINGS["panic_freespace"] else ""}),
                           encoding="utf-8")
            (DATA / "wipe_on_start").write_text("1")      # fallback if the helper is blocked
            cmd = ([sys.executable, "--wipe", str(job)] if IS_FROZEN
                   else [sys.executable, str(Path(__file__).resolve()), "--wipe", str(job)])
            kw = {"creationflags": 0x00000008 | 0x08000000} if sys.platform == "win32" else {"start_new_session": True}
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, close_fds=True, **kw)
            QApplication.clipboard().clear()
            kill_nova_processes()
        finally:
            os._exit(0)

    def get_secret(self, name, label, force=False):
        if not force and name in self._secrets:
            return self._secrets[name]
        val = None if force else (load_json(VAULT_FILE, {}).get(name) if KEY is not None else None)
        if not val:
            val, ok = QInputDialog.getText(self, label, f"{label}:", QLineEdit.EchoMode.Password)
            val = val.strip() if ok else ""
            if not val:
                return None
            if KEY is not None:
                v = load_json(VAULT_FILE, {})
                v[name] = val
                save_json(VAULT_FILE, v)
        self._secrets[name] = val
        return val

    def on_download_done(self, it, folder):
        if not it.isFinished() or it.state() != QWebEngineDownloadRequest.DownloadState.DownloadCompleted:
            return
        path = Path(it.downloadDirectory()) / it.downloadFileName()
        self.statusBar().showMessage(f"Downloaded {path.name} → {folder}", 8000)
        add_motw(path, it.url().toString())
        self.dl_items.append({"name": path.name, "path": str(path)})
        if not self.ephemeral:
            log = load_json(DOWNLOADS_LOG, [])
            log.append(str(path))
            save_json(DOWNLOADS_LOG, log[-500:])
        if SETTINGS["av_scan"]:
            self.scan_file(path)

    def scan_file(self, path, manual=False):
        key = self.get_secret("vt_key", "VirusTotal API key") if (SETTINGS["av_vt"] and not self.tor) else None
        th = ScanThread(path, key)
        th.done.connect(lambda rep: self.on_scan_result(rep, manual))
        self.run_thread(th)
        self.statusBar().showMessage(f"Scanning {Path(path).name}…", 5000)

    def scan_pick_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Scan a file")
        if f:
            self.scan_file(Path(f), True)

    def scan_downloads(self):
        self.scan_file(Path.home() / "Downloads", True)

    def on_scan_result(self, rep, manual):
        v, path = av_verdict(rep), Path(rep["path"])
        d = {"clean": "no threat found", "threat": "THREAT DETECTED", "unavailable": "not available on this PC",
             "error": "scan failed", "n/a": "n/a"}.get(rep["defender"], rep["defender"])
        lines = [f"Microsoft Defender: {d}"]
        vt = rep.get("vt")
        if isinstance(vt, dict):
            lines.append(f"VirusTotal: {vt['malicious']} engines flag it as malicious")
        elif vt == "unknown":
            lines.append("VirusTotal: file never seen before (not proof it is safe)")
        lines += ["⚠ " + f for f in rep["flags"]]
        if rep["defender"] in ("unavailable", "error") and not isinstance(vt, dict):
            lines.append("No antivirus engine could scan this — only basic checks ran.")
        detail = "\n".join(lines)
        if v == "threat":
            if rep.get("dir"):
                QMessageBox.critical(self, "Antivirus", f"Threat found in {path}.\n\n{detail}\n\n"
                                     "Open Windows Security → Protection history to remove it.")
                return
            try:
                quarantine(path, rep, "; ".join(lines[:2]))
                QMessageBox.critical(self, "Antivirus — threat blocked",
                                     f"{path.name} was moved to quarantine.\n\n{detail}")
            except OSError as e:
                QMessageBox.critical(self, "Antivirus", f"Threat in {path.name} but quarantine failed: {e}\n\n{detail}")
        elif v == "suspicious":
            if QMessageBox.question(self, "Antivirus — suspicious file", f"{path.name}\n\n{detail}\n\nDelete it?"
                                    ) == QMessageBox.StandardButton.Yes:
                secure_delete(path)
        elif manual:
            QMessageBox.information(self, "Antivirus", f"{path.name}: clean\n\n{detail}")
        else:
            self.statusBar().showMessage(f"✔ {path.name} scanned — clean", 6000)

    def open_quarantine(self):
        QuarantineDialog(self).exec()

    def store_vpn_creds(self, name, user, pw):
        self._secrets[f"vpn:{name}"] = (user, pw)
        if KEY is not None:
            v = load_json(VAULT_FILE, {})
            v.setdefault("vpn", {})[name] = {"u": user, "p": pw}
            save_json(VAULT_FILE, v)
        else:
            QMessageBox.information(self, "VPN", "Login kept for this session only. Set a master password "
                                    "(☰ → Security & privacy) to save it encrypted.")

    def vpn_credentials(self, name):
        k = f"vpn:{name}"
        if k in self._secrets:
            return self._secrets[k]
        if KEY is not None:
            c = load_json(VAULT_FILE, {}).get("vpn", {}).get(name)
            if c:
                self._secrets[k] = (c["u"], c["p"])
                return self._secrets[k]
        u, ok = QInputDialog.getText(self, "VPN login", f"Username for {name}:")
        if not ok:
            return None
        p, ok = QInputDialog.getText(self, "VPN login", "Password:", QLineEdit.EchoMode.Password)
        if not ok:
            return None
        self._secrets[k] = (u, p)
        return self._secrets[k]

    def on_proxy_auth(self, url, auth, host):
        if SETTINGS["vpn_active"]:
            c = self.vpn_credentials(SETTINGS["vpn_active"])
            if c:
                auth.setUser(c[0])
                auth.setPassword(c[1])

    def restart_app(self):
        cmd = [sys.executable] if IS_FROZEN else [sys.executable, str(Path(__file__).resolve())]
        if not self.ephemeral:
            save_json(SESSION_FILE, self.open_urls())
        subprocess.Popen(cmd + (["--profile", PROFILE] if PROFILE else []) + ["--restore", "--after", str(os.getpid())])
        QApplication.closeAllWindows()
        QApplication.quit()

    def verify_manifest(self, m):
        try:
            pub = base64.b64decode(SETTINGS["update_pubkey"].strip() or DEFAULT_UPDATE_PUBKEY)
            msg = f'{m["version"]}|{m["url"]}|{m["sha256"]}'.encode()
            Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(m["sig"]), msg)
            return True
        except Exception:
            return False

    # ================================================================ shutdown
    def closeEvent(self, e):
        if self.chroma:
            self.chroma.stop()
        for fw in list(self._floats):
            fw.close()
        if self.tor_proc:
            self.tor_proc.kill()
        if not self.ephemeral:
            save_json(HISTORY_FILE, self.history)
            save_json(SESSION_FILE, self.open_urls())
        if SETTINGS["clear_on_exit"] and not self.private:
            for f in (HISTORY_FILE, SESSION_FILE):
                f.unlink(missing_ok=True)
            (DATA / "wipe_on_start").write_text("1")
        for v in self._dev:
            v.close()
        super().closeEvent(e)


PRIVATE_WINDOWS = []

if __name__ == "__main__":
    if "--wipe" in sys.argv:           # detached helper started by Panic Wipe
        run_wipe_helper()
        sys.exit(0)
    if "--after" in sys.argv:          # restart: wait for the previous instance to exit
        try:
            psutil.wait_procs([psutil.Process(int(sys.argv[sys.argv.index("--after") + 1]))], timeout=20)
        except (psutil.Error, ValueError, IndexError):
            pass
    if "--restore" in sys.argv:
        SETTINGS["restore_session"] = True
    tor_mode = "--tor" in sys.argv
    tor_exe = None
    QApplication.setApplicationName("Nova")
    QApplication.setOrganizationName("Nova")
    wipe_storage()
    FILTERS.load()
    SHIELDS.allblock = BUILTIN_BLOCK | FILTERS.block
    SHIELDS.hostsblock = FILTERS.hosts
    SHIELDS.badurls = FILTERS.badurls
    ensure_samples()
    qt_args = [sys.argv[0]] + PRIVACY_FLAGS
    if tor_mode:
        port, tor_exe = pick_tor_port()
        if port is None:
            app = QApplication(qt_args)
            app.setStyleSheet(make_qss(*theme()))
            QMessageBox.critical(None, "Nova — Tor not found",
                                 "No Tor found.\n\nPut the Tor Expert Bundle in a 'tor' folder next to Nova "
                                 "(tor\\tor\\tor.exe), or start Tor Browser first.")
            sys.exit(1)
        qt_args += [f"--proxy-server=socks5://127.0.0.1:{port}",
                    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
    else:
        qt_args.append("--force-webrtc-ip-handling-policy=" +
                       ("disable_non_proxied_udp" if active_vpn_url() else "default_public_interface_only"))
        doh = "" if active_vpn_url() else DOH.get(SETTINGS["doh"], "")
        if doh:   # best-effort: Chromium field-trial switches for secure DNS
            qt_args += ["--enable-features=DnsOverHttps<DoHTrial", "--force-fieldtrials=DoHTrial/Group1",
                        "--force-fieldtrial-params=DoHTrial.Group1:server/" + quote(doh, safe="") + "/method/POST"]
        if active_vpn_url():
            qt_args.append(f"--proxy-server={active_vpn_url()}")    # proxy VPN: fail-closed, DNS via proxy
        elif SETTINGS["proxy"]:
            qt_args.append(f"--proxy-server={SETTINGS['proxy']}")
        elif SETTINGS["net_limit"]:
            THROTTLE = ThrottleProxy()
            THROTTLE.start()
            if THROTTLE.ready.wait(5):
                qt_args.append(f"--proxy-server=http://127.0.0.1:{THROTTLE.port}")
        if SETTINGS["drm"]:
            wv = find_widevine()
            if wv:
                qt_args.append(f"--widevine-path={wv}")
    app = QApplication(qt_args)
    app.setStyle("Fusion")
    apply_theme(app)
    if (APP_DIR / "nova.ico").exists():
        app.setWindowIcon(QIcon(str(APP_DIR / "nova.ico")))
    start_urls = [a for a in sys.argv[1:] if a.lower().startswith(("http://", "https://", "file://"))]
    if not tor_mode and send_to_running(start_urls):
        sys.exit(0)                     # Nova is already open: links go to the running window
    if not tor_mode and not unlock_flow():
        sys.exit(1)
    win = Browser(tor=tor_mode, tor_exe=tor_exe, start_urls=None if tor_mode else start_urls)
    if not tor_mode:
        INSTANCE_SERVER.append(start_instance_server(win))
    win.show()
    sys.exit(app.exec())
