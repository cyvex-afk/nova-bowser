#!/usr/bin/env bash
# EXPERIMENTAL macOS build (untested by the author). Produces Nova-macos.zip
# Unsigned apps trigger Gatekeeper; distribute widely only after Apple code-signing + notarization.
set -e
cd "$(dirname "$0")"
rm -rf .venv build dist
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install "PyQt6>=6.7,<6.8" "PyQt6-Qt6>=6.7,<6.8" "PyQt6-WebEngine>=6.7,<6.8" "PyQt6-WebEngine-Qt6>=6.7,<6.8" psutil cryptography pyinstaller
python -c "from PyQt6.QtWebEngineWidgets import QWebEngineView; print('Qt WebEngine OK')"
pyinstaller --noconfirm --windowed --name Nova --osx-bundle-identifier com.example.nova --add-data "nova.ico:." nova_browser.py
ditto -c -k --keepParent dist/Nova.app Nova-macos.zip
echo "Done -> Nova-macos.zip"
