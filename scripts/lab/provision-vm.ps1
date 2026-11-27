<#
FatBox: prepare a test VM. Runs INSIDE the VM, never on the host. Three ways to use it:

 a) One PC, zero-touch (T-23, 0.40.0): run scripts\setup-host.ps1 on the host. It puts this script on a
    "FatBox setup" disc in the VM, with VirtualBox's Guest Additions disc beside it. In the VM, open the
    FatBox disc and double-click Setup.cmd (one "Yes"). Nothing else is done by hand in the VM.
 b) Automatic from an ISO: new-test-vm.ps1 builds a VM from a Windows ISO and runs this through guest control.
 c) By hand on your own fresh VM (Guest Additions installed, local account with a password, network on), one
    line in PowerShell "Run as administrator" inside the VM (public repo, no token):
        irm https://raw.githubusercontent.com/Knight007-hash/fatbox-beta/main/scripts/lab/provision-vm.ps1 -OutFile $env:TEMP\p.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\p.ps1
    then shut the VM down, run lock-vm.ps1 on the PC that runs VirtualBox, and FatBox GUI -> Make clean snapshot.

What it does:
 - (disc only) installs the Guest Additions silently from the VirtualBox disc (signer checked), creates the
   local admin user 'fatbox' that the host's guest control logs in as, with the password setup-host.ps1 made;
 - Windows Update and SmartScreen off; Defender: exclusion for C:\fatbox, real-time protection off when Tamper
   Protection allows it, automatic sample submission (MAPS) off; sleep and hibernate off;
 - installs the VC++ x64 runtime, Python 3.13 and Git for Windows (each installer's Authenticode signer is
   checked before it runs), clones FatBox (VM side only) to C:\fatbox and installs its pinned libraries;
 - the MalwareBazaar key: from the disc, or asked once (Enter = later).
0.42.0: from the disc (a) or new-test-vm.ps1 (b), FatBox comes from the host as a git bundle (-Bundle): the VM
never contacts GitHub for FatBox. By hand (c): a plain clone of the public repo. It never asks for a GitHub token.
#>
param(
    [string]$TokenFile = "",
    [string]$Bundle = "",                       # 0.42.0: the host's FatBox code (git bundle); no GitHub, no token
    [switch]$NoPrompt,                          # unattended (new-test-vm.ps1): never ask anything
    [switch]$FromDisc,                          # T-23: settings come from fatbox-setup.json next to this script
    [string]$Repo = "https://github.com/Knight007-hash/fatbox-beta.git",
    [string]$PythonVersion = "3.13.9",
    [string]$GitUrl = "https://github.com/git-for-windows/git/releases/download/v2.51.0.windows.1/Git-2.51.0-64-bit.exe",
    [string]$Dest = "C:\fatbox"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is very slow with the progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Say($t) { Write-Host "[vm] $t" -ForegroundColor Cyan }

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this as administrator (on the FatBox disc: double-click Setup.cmd and click Yes)."
}

$setup = $null
if ($FromDisc) {
    $NoPrompt = $true
    $cfgFile = Join-Path $PSScriptRoot "fatbox-setup.json"
    if (-not (Test-Path $cfgFile)) { throw "fatbox-setup.json is not on the FatBox disc: run scripts\setup-host.ps1 on the host again." }
    $setup = Get-Content $cfgFile -Raw | ConvertFrom-Json
    if ($setup.user -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$') { throw "bad user name in fatbox-setup.json" }
    if ([string]$setup.password -notmatch '^[A-Za-z0-9]{16,64}$') { throw "bad password in fatbox-setup.json" }
    if ($setup.repo -notmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw "bad repo URL in fatbox-setup.json" }
    $Repo = $setup.repo
    $b = Join-Path $PSScriptRoot "fatbox.bundle"
    if (-not $Bundle -and (Test-Path $b)) { $Bundle = $b }
}
if ($Bundle -and -not (Test-Path $Bundle)) { throw "FatBox code bundle not found: $Bundle" }
$marker = Join-Path $Dest "setup-done.txt"     # setup-host.ps1 waits for this file
Remove-Item $marker -Force -ErrorAction SilentlyContinue

function Get-Signed($url, $out, $signer) {
    Say "download $url"
    for ($i = 1; $i -le 4; $i++) {
        try { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 900; break }
        catch { if ($i -eq 4) { throw "download failed: $url (is the VM's network on?)" }; Start-Sleep ($i * 10) }
    }
    Assert-Signed $out $signer
}
function Assert-Signed($file, $signer) {
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch $signer) {
        throw "$file is not validly signed by '$signer' (status $($sig.Status)); not running it"
    }
}

# 1. Guest Additions: FatBox talks to the VM only through them (guest control)
$restart = $false
if (-not (Get-Service VBoxService -ErrorAction SilentlyContinue)) {
    $ga = Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Root } |
        Where-Object { Test-Path (Join-Path $_ "VBoxWindowsAdditions-amd64.exe") } | Select-Object -First 1
    if (-not $ga) {
        throw "VirtualBox Guest Additions are not installed and their disc is not in the VM. On the host: run scripts\setup-host.ps1 (it inserts the disc), or in the VM window: Devices > Insert Guest Additions CD image."
    }
    $exe = Join-Path $ga "VBoxWindowsAdditions-amd64.exe"
    Assert-Signed $exe "Oracle"
    Say "install VirtualBox Guest Additions from $ga (silent)"
    $cu = Join-Path $ga "cert\VBoxCertUtil.exe"
    if (Test-Path $cu) {   # trust Oracle's driver certificate first, so Windows shows no "install this driver?" box
        Assert-Signed $cu "Oracle"
        Push-Location (Join-Path $ga "cert")
        & $cu add-trusted-publisher vbox*.cer --root vbox*.cer | Out-Null
        Pop-Location
    }
    $p = Start-Process $exe -ArgumentList "/S" -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010) { throw "Guest Additions install failed ($($p.ExitCode))" }
    $restart = $true
}

# 2. The account the host logs in as (disc setup): local admin 'fatbox', password made by setup-host.ps1.
#    The client's own account is not touched. Hidden from the sign-in screen.
if ($setup) {
    Say "user '$($setup.user)' for FatBox's guest control (local administrator)"
    $pw = ConvertTo-SecureString ([string]$setup.password) -AsPlainText -Force
    if (Get-LocalUser -Name $setup.user -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $setup.user -Password $pw -PasswordNeverExpires $true
        Enable-LocalUser -Name $setup.user
    } else {
        New-LocalUser -Name $setup.user -Password $pw -PasswordNeverExpires -AccountNeverExpires `
            -Description "FatBox guest control" | Out-Null
    }
    $admins = (Get-LocalGroup -SID "S-1-5-32-544").Name
    try { Add-LocalGroupMember -Group $admins -Member $setup.user }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'MemberExists') { throw } }
    $pw = $null
    $hide = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    New-Item -Path $hide -Force | Out-Null
    Set-ItemProperty -Path $hide -Name $setup.user -Value 0 -Type DWord
    # FatBox commands run with full admin rights, as in new-test-vm.ps1 (samples are never run, INV-3)
    $sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if ((Get-ItemProperty -Path $sys -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA -ne 0) {
        Set-ItemProperty -Path $sys -Name EnableLUA -Value 0 -Type DWord
        $restart = $true
    }
}

# Public repo: no token, never asked. -TokenFile only for a private copy.
$token = ""
if ($TokenFile) {
    $token = (Get-Content $TokenFile -Raw).Trim()
    Remove-Item $TokenFile -Force
    if ($token -notmatch '^[A-Za-z0-9_]{20,255}$') { throw "token file is not a GitHub token" }
}

$dl = "C:\fatbox-setup\dl"
New-Item -ItemType Directory -Force -Path $dl | Out-Null

# 3. Windows Update and SmartScreen off, Defender out of FatBox's way (SPEC section 2, T-10)
Say "Windows Update off, SmartScreen off, Defender exclusion for $Dest, sample upload off, sleep off"
$au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name NoAutoUpdate -Value 1 -Type DWord
foreach ($svc in "wuauserv", "UsoSvc") {
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}
$ss = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
New-Item -Path $ss -Force | Out-Null
Set-ItemProperty -Path $ss -Name EnableSmartScreen -Value 0 -Type DWord
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Add-MpPreference -ExclusionPath $Dest -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionProcess "C:\Python313\python.exe" -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
# Never send files from this VM to Microsoft: SubmitSamplesConsent 2 = never send, MAPS reporting off
Set-MpPreference -SubmitSamplesConsent 2 -MAPSReporting 0 -ErrorAction SilentlyContinue
$spy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
New-Item -Path $spy -Force | Out-Null
Set-ItemProperty -Path $spy -Name SubmitSamplesConsent -Value 2 -Type DWord
Set-ItemProperty -Path $spy -Name SpynetReporting -Value 0 -Type DWord
$mp = Get-MpPreference -ErrorAction SilentlyContinue
if ($mp -and $mp.SubmitSamplesConsent -ne 2) {
    Write-Warning "Defender still may send samples to Microsoft (Tamper Protection). Samples stay in password zips Defender can't open, but to be sure: Windows Security > Virus & threat protection > Manage settings > Tamper Protection off, then Automatic sample submission off."
}
if ((Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled) {
    Write-Warning "Defender real-time protection is still on (Tamper Protection). FatBox works with the exclusion; to turn it off: Windows Security > Virus & threat protection > Manage settings > Tamper Protection off, then Real-time protection off."
}
foreach ($t in "standby-timeout-ac", "standby-timeout-dc", "hibernate-timeout-ac", "hibernate-timeout-dc", "monitor-timeout-ac") {
    powercfg /change $t 0 | Out-Null
}
powercfg /hibernate off | Out-Null

# 4. VC++ runtime (File Analysis needs it)
$vc = Join-Path $dl "vc_redist.x64.exe"
Get-Signed "https://aka.ms/vs/17/release/vc_redist.x64.exe" $vc "Microsoft Corporation"
Say "install VC++ runtime"
$p = Start-Process $vc -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru
if ($p.ExitCode -notin 0, 1638, 3010) { throw "VC++ runtime install failed ($($p.ExitCode))" }

# Python 3.13 (all users, C:\Python313: the path host.toml's guest_python uses)
$pyExe = "C:\Python313\python.exe"
if (-not (Test-Path $pyExe)) {
    $pi = Join-Path $dl "python-$PythonVersion-amd64.exe"
    Get-Signed "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe" $pi "Python Software Foundation"
    Say "install Python $PythonVersion"
    $p = Start-Process $pi -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0", "TargetDir=C:\Python313" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Python install failed ($($p.ExitCode))" }
}

# Git for Windows
$git = "C:\Program Files\Git\cmd\git.exe"
if (-not (Test-Path $git)) {
    $gi = Join-Path $dl "git-setup.exe"
    Get-Signed $GitUrl $gi "Johannes Schindelin"
    Say "install Git"
    $p = Start-Process $gi -ArgumentList "/VERYSILENT", "/NORESTART", "/NOCANCEL", "/SP-", "/SUPPRESSMSGBOXES" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Git install failed ($($p.ExitCode))" }
}

$env:Path = "C:\Program Files\Git\cmd;C:\Python313;C:\Python313\Scripts;" + $env:Path   # fresh installs
$env:GIT_TERMINAL_PROMPT = "0"                 # a refused clone fails at once instead of opening a sign-in box

# 5. FatBox, VM side. A token travels as a one-off header (as fatbox update does), never in .git\config.
function Clone-FatBox($tok) {
    $auth = @("-c", "credential.helper=")
    if ($tok) {
        $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$tok"))
        $auth += @("-c", "http.https://github.com/.extraheader=Authorization: Basic $basic")
    }
    & $git @auth clone $Repo $Dest | Out-Host
    return ($LASTEXITCODE -eq 0)
}
if ($Bundle -and -not (Test-Path (Join-Path $Dest ".git"))) {
    Say "FatBox code from the host (no GitHub, no token) to $Dest"
    Get-ChildItem $Dest -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "setup-done.txt" } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue   # git clones only into an empty folder
    & $git clone --quiet $Bundle $Dest | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "git clone from the host's bundle failed" }
    & $git -C $Dest checkout --quiet -B main | Out-Host                   # a bundle of HEAD clones detached
    & $git -C $Dest remote set-url origin $Repo | Out-Host
}
if (-not (Test-Path (Join-Path $Dest ".git"))) {
    Say "clone FatBox from $Repo to $Dest"
    Get-ChildItem $Dest -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "setup-done.txt" } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue   # git clones only into an empty folder
    $ok = Clone-FatBox $token
    if (-not $ok) { throw "git clone failed: is the VM's network on? (the public repo needs no account or token)" }
}
if ($token) {   # where 'python -m fatbox update' reads it (fatbox/updater.py TOKEN_FILE)
    $tf = Join-Path $env:USERPROFILE ".fatbox\github-token"
    New-Item -ItemType Directory -Force -Path (Split-Path $tf) | Out-Null
    [IO.File]::WriteAllText($tf, "$token`n", (New-Object Text.UTF8Encoding $false))
}
$token = $null
Say "install FatBox libraries (pinned, with hashes)"
Push-Location $Dest
if (-not (Test-Path "config.toml")) { Copy-Item "config.example.toml" "config.toml" }
& $pyExe -m pip install --disable-pip-version-check --require-hashes --only-binary :all: -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
if ($Bundle) { & $pyExe -m fatbox update --no-fetch }   # narrows the folder to the VM files (updater.VM_FILES)
else { & $pyExe -m fatbox update }                         # same, after a check with GitHub
$version = (& $pyExe -m fatbox --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "FatBox does not start" }
Pop-Location

Remove-Item $dl -Recurse -Force -ErrorAction SilentlyContinue
# 6. The MalwareBazaar key (free: https://auth.abuse.ch/). From the disc it is set for every user of the VM,
#    so the 'fatbox' user that guest control logs in as sees it.
if ($setup -and $setup.mb_api_key) {
    if ([string]$setup.mb_api_key -notmatch '^[A-Za-z0-9]{16,128}$') { Write-Warning "the MalwareBazaar key on the disc looks wrong; set it later" }
    else { [Environment]::SetEnvironmentVariable("MB_API_KEY", [string]$setup.mb_api_key, "Machine"); Say "MB_API_KEY saved" }
} elseif (-not $NoPrompt -and -not [Environment]::GetEnvironmentVariable("MB_API_KEY", "User")) {
    $k = (Read-Host "MalwareBazaar API key (free at https://auth.abuse.ch/; Enter = set it later)").Trim()
    if ($k) { [Environment]::SetEnvironmentVariable("MB_API_KEY", $k, "User"); Say "MB_API_KEY saved for $env:USERNAME" }
}
$setup = $null

[IO.File]::WriteAllText($marker, "$version`n", (New-Object Text.UTF8Encoding $false))
Say "provisioning done ($version). For host.toml: guest_python = '$pyExe', guest_dir = '$Dest'"
if ($FromDisc) {
    if ($restart) {
        Say "restarting the VM in 15 s (Guest Additions and the admin setting need it). The host finishes the rest."
        shutdown.exe /r /t 15 /c "FatBox setup: restart" | Out-Null
    } else {
        Say "All done in the VM. The host finishes the rest; you can close this window."
    }
}
