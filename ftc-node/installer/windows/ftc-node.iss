; FTC Node - Professional Windows Installer
; Inno Setup Script
; Kristian Pilatovich 20091227

#define AppName "FTC Node"
#define AppVersion "1.0.2"
#define AppPublisher "Flow Token Chain"
#define AppURL "https://github.com/user/ftc-node"
#define AppExeName "ftc-node.exe"

[Setup]
AppId={{F7C8A9B1-2D3E-4F5A-6B7C-8D9E0F1A2B3C}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\FTC Node
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=..\..\..\release
OutputBaseFilename=ftc-node-{#AppVersion}-win64-setup
SetupIconFile=..\..\assets\ftc-node.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\ftc-node.ico
SetupLogging=yes
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "firewall"; Description: "Configure Windows Firewall"; GroupDescription: "Network:"
Name: "autostart"; Description: "Start FTC Node with Windows"; GroupDescription: "Startup:"

[Files]
; Main executable
Source: "..\..\..\release\ftc-node.exe"; DestDir: "{app}"; Flags: ignoreversion

; Application icon
Source: "..\..\assets\ftc-node.ico"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\FTC"; Permissions: users-full
Name: "{commonappdata}\FTC\blocks"; Permissions: users-full
Name: "{commonappdata}\FTC\chainstate"; Permissions: users-full

[Icons]
; Start Menu - start node
Name: "{group}\FTC Node"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ftc-node.ico"; Comment: "Start FTC Node"

; Start Menu - data folder
Name: "{group}\Data Folder"; Filename: "{commonappdata}\FTC"

; Start Menu - uninstall
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"

; Desktop shortcut
Name: "{autodesktop}\FTC Node"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ftc-node.ico"; Tasks: desktopicon

; Startup folder (auto-start)
Name: "{userstartup}\FTC Node"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ftc-node.ico"; Tasks: autostart

[Registry]
Root: HKLM; Subkey: "SOFTWARE\FTC Node"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\FTC Node"; ValueType: string; ValueName: "DataPath"; ValueData: "{commonappdata}\FTC"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\FTC Node"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"; Flags: uninsdeletekey

[Run]
; After install - start node
Filename: "{app}\{#AppExeName}"; Description: "Start FTC Node"; Flags: postinstall nowait skipifsilent

[Code]
procedure ConfigureFirewall();
var
  ResultCode: Integer;
begin
  Exec('netsh.exe', 'advfirewall firewall add rule name="FTC Node P2P" dir=in action=allow protocol=tcp localport=17318 profile=any',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('netsh.exe', 'advfirewall firewall add rule name="FTC Node API" dir=in action=allow protocol=tcp localport=17319 profile=any',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('netsh.exe', 'advfirewall firewall add rule name="FTC Node DHT" dir=in action=allow protocol=udp localport=17321 profile=any',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure RemoveFirewallRules();
var
  ResultCode: Integer;
begin
  Exec('netsh.exe', 'advfirewall firewall delete rule name="FTC Node P2P"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('netsh.exe', 'advfirewall firewall delete rule name="FTC Node API"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('netsh.exe', 'advfirewall firewall delete rule name="FTC Node DHT"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StopRunningNode();
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM ftc-node.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  StopRunningNode();
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('firewall') then
      ConfigureFirewall();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopRunningNode();
    RemoveFirewallRules();
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := '';

  if MemoDirInfo <> '' then
    Result := Result + MemoDirInfo + NewLine + NewLine;

  if MemoTasksInfo <> '' then
    Result := Result + MemoTasksInfo + NewLine + NewLine;

  Result := Result + 'Network Ports:' + NewLine;
  Result := Result + Space + 'P2P: 17318 (TCP)' + NewLine;
  Result := Result + Space + 'API: 17319 (TCP)' + NewLine;
  Result := Result + Space + 'DHT: 17321 (UDP)' + NewLine + NewLine;

  Result := Result + 'HTTP API: http://localhost:17319' + NewLine;
  Result := Result + 'Data: ' + ExpandConstant('{commonappdata}\FTC');
end;
