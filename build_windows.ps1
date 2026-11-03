# One-shot build: creates dist\Nova\Nova.exe (and Output\NovaSetup.exe if Inno Setup is installed).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Install Python 3.10-3.12 from python.org (tick 'Add to PATH'), then run build.bat again."
    exit 1
}

Write-Host "== Fresh build environment =="
foreach ($d in ".venv", "build", "dist") { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip

# All four Qt packages MUST be the same 6.7.x release. Mixed versions cause
# "DLL load failed while importing QtWebEngineCore: The specified procedure could not be found".
pip install "PyQt6>=6.7,<6.8" "PyQt6-Qt6>=6.7,<6.8" "PyQt6-WebEngine>=6.7,<6.8" "PyQt6-WebEngine-Qt6>=6.7,<6.8" psutil cryptography pyinstaller

Write-Host "== Checking Qt WebEngine loads =="
python -c "from PyQt6.QtWebEngineWidgets import QWebEngineView; from PyQt6.QtCore import QT_VERSION_STR; print('Qt WebEngine OK, Qt', QT_VERSION_STR)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nQt WebEngine failed to load on this PC."
    Write-Host "Install the Microsoft Visual C++ Redistributable (x64): https://aka.ms/vs/17/release/vc_redist.x64.exe"
    Write-Host "Also make sure no other program's Qt6*.dll folder is on your PATH. Then run build.bat again."
    exit 1
}

# ---- Tor Expert Bundle (downloaded from the official Tor Project server, hash-checked) ----
if (-not (Test-Path "tor\tor\tor.exe")) {
    Write-Host "== Fetching Tor Expert Bundle =="
    try {
        $base  = "https://dist.torproject.org/torbrowser/"
        $vers  = (Invoke-WebRequest $base -UseBasicParsing).Links.href |
                 Where-Object { $_ -match '^\d+\.\d+(\.\d+)?/$' } | ForEach-Object { $_.TrimEnd('/') }
        $ver   = $vers | Sort-Object { [version]$_ } | Select-Object -Last 1
        $file  = "tor-expert-bundle-windows-x86_64-$ver.tar.gz"
        $tmp   = Join-Path $env:TEMP $file
        Invoke-WebRequest "$base$ver/$file" -OutFile $tmp -UseBasicParsing

        $sums  = (Invoke-WebRequest "$base$ver/sha256sums-signed-build.txt" -UseBasicParsing).Content
        $line  = ($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($file) } | Select-Object -First 1
        $want  = ($line.Trim() -split '\s+')[0]
        $have  = (Get-FileHash $tmp -Algorithm SHA256).Hash
        if ($want -ne $have) { throw "Checksum mismatch - refusing to use download." }

        New-Item -ItemType Directory -Force -Path "tor" | Out-Null
        tar -xzf $tmp -C "tor"
        Write-Host "Tor $ver bundled."
    } catch {
        Write-Host "Could not fetch Tor automatically ($_)."
        Write-Host "Building without bundled Tor. To add it: extract the Tor Expert Bundle so 'tor\tor\tor.exe' exists, then re-run."
    }
}

Write-Host "== Building Nova.exe =="
$opts = @("--noconfirm", "--windowed", "--name", "Nova", "--icon", "nova.ico", "--add-data", "nova.ico;.")
if (Test-Path "tor") { $opts += @("--add-data", "tor;tor") }
pyinstaller @opts nova_browser.py

# ---- Optional installer ----
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc installer.iss
    Write-Host "`nInstaller ready: Output\NovaSetup.exe"
} else {
    Write-Host "`nApp ready: dist\Nova\Nova.exe"
    Write-Host "For a proper installer: winget install JRSoftware.InnoSetup, then run build.bat again."
}
