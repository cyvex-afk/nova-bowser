#!/usr/bin/env bash
# EXPERIMENTAL Linux build (untested by the author). Produces Nova-linux.tar.gz
set -e
cd "$(dirname "$0")"
rm -rf .venv build dist
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
# all four Qt packages must be the same 6.7.x release
pip install "PyQt6>=6.7,<6.8" "PyQt6-Qt6>=6.7,<6.8" "PyQt6-WebEngine>=6.7,<6.8" "PyQt6-WebEngine-Qt6>=6.7,<6.8" psutil cryptography pyinstaller
python -c "from PyQt6.QtWebEngineWidgets import QWebEngineView; print('Qt WebEngine OK')"
pyinstaller --noconfirm --windowed --name Nova --add-data "nova.ico:." nova_browser.py
tar -czf Nova-linux.tar.gz -C dist Nova
echo "Done -> Nova-linux.tar.gz  (Windows-only features such as Defender scanning are unavailable on Linux)"
