; Nova installer — compile with Inno Setup 6.3+ (build.bat does this automatically if it's installed).
; Edit the three #define lines below before you publish.
#define MyAppName "Nova"
#define MyAppVersion "1.5.0"
#define MyAppPublisher "Your Name or Company"
#define MyAppURL "https://yourdomain.com"
#define MyAppExe "Nova.exe"

[Setup]
AppId={{B3F1C0E2-6A44-4E0B-9A57-7E2A8C5D1F10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Nova
DefaultGroupName=Nova
DisableProgramGroupPage=yes
; Per-user install by default (no admin prompt); the user may choose "all users" in the dialog.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=nova.ico
UninstallDisplayIcon={app}\{#MyAppExe}
OutputBaseFilename=NovaSetup
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
; LicenseFile=LICENSE.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "dist\Nova\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Nova"; Filename: "{app}\{#MyAppExe}"
Name: "{autoprograms}\Nova (Tor window)"; Filename: "{app}\{#MyAppExe}"; Parameters: "--tor"
Name: "{autodesktop}\Nova"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

; Makes Nova appear in Windows Settings > Default apps (http, https, .htm, .html)
[Registry]
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova"; ValueType: string; ValueData: "Nova"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\DefaultIcon"; ValueType: string; ValueData: "{app}\{#MyAppExe},0"
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\shell\open\command"; ValueType: string; ValueData: """{app}\{#MyAppExe}"""
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\Capabilities"; ValueType: string; ValueName: "ApplicationName"; ValueData: "Nova"
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\Capabilities"; ValueType: string; ValueName: "ApplicationDescription"; ValueData: "Private browser with built-in shields, Tor, VPN support and download scanning"
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\Capabilities\URLAssociations"; ValueType: string; ValueName: "http"; ValueData: "NovaHTML"
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\Capabilities\URLAssociations"; ValueType: string; ValueName: "https"; ValueData: "NovaHTML"
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\Capabilities\FileAssociations"; ValueType: string; ValueName: ".htm"; ValueData: "NovaHTML"
Root: HKA; Subkey: "Software\Clients\StartMenuInternet\Nova\Capabilities\FileAssociations"; ValueType: string; ValueName: ".html"; ValueData: "NovaHTML"
Root: HKA; Subkey: "Software\RegisteredApplications"; ValueType: string; ValueName: "Nova"; ValueData: "Software\Clients\StartMenuInternet\Nova\Capabilities"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\NovaHTML"; ValueType: string; ValueData: "Nova HTML Document"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\NovaHTML\DefaultIcon"; ValueType: string; ValueData: "{app}\{#MyAppExe},0"
Root: HKA; Subkey: "Software\Classes\NovaHTML\shell\open\command"; ValueType: string; ValueData: """{app}\{#MyAppExe}"" ""%1"""

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Launch Nova"; Flags: nowait postinstall skipifsilent
Filename: "ms-settings:defaultapps"; Description: "Open Default apps to choose Nova as your browser"; Flags: shellexec postinstall skipifsilent unchecked
