<#
FatBox: one-script setup for the One PC layout (T-23). Run on the host PC, in a normal PowerShell, from the
folder you cloned FatBox into:

  powershell -ExecutionPolicy Bypass -File .\scripts\setup-host.ps1

You need: VirtualBox 7, and a fresh Windows 10/11 VM in it, powered off. Nothing is set up by hand inside the VM.

What it does (each step says so as it runs):
 1. Host: Python 3.11+ (installs 3.13 for your user if missing, signer checked), FatBox's .venv, desktop shortcut.
 2. Lets you pick the VM; asks once for the free MalwareBazaar key (Enter = later).
 3. Makes a random password for a local user 'fatbox' in the VM (your own VM account is not touched), saves it
    in %APPDATA%\fatbox-host\guest.pw (only you can read it) and writes host.toml for this VM.
 4. Safe VM settings: NAT, VM cannot reach this PC's own services, clipboard / drag-and-drop / shared folders /
    USB / audio / 3D off (INV-6).
 5. Puts two discs in the VM: "FatBox setup" (Setup.cmd + provision-vm.ps1 + a one-off settings file) and
    VirtualBox's Guest Additions. Plugs the network in and starts the VM.
 6. You: sign in to Windows in the VM, open the FatBox disc, double-click Setup.cmd, click Yes. That's all.
 7. Waits until FatBox answers in the VM, then ALWAYS (also on an error or Ctrl+C): network unplugged (INV-7),
    discs taken out, the setup disc file deleted.
Then: FatBox Host (desktop) -> Snapshots -> Make clean snapshot.
#>
param(
    [string]$Vm = "",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    [string]$GuestUser = "fatbox",
    [int]$WaitMin = 180
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Say($t) { Write-Host "==> $t" -ForegroundColor Cyan }
function Quiet {   # a native command whose error text is not wanted (Windows PowerShell 5.1 throws on 2> under Stop)
    $ErrorActionPreference = "Continue"
    $exe, $rest = $args
    (& $exe @rest 2>&1 | Out-String)
}
function VBM {
    & $VBoxManage @args
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args[0]) $($args[1]) failed (exit $LASTEXITCODE)" }
}

function Select-Vm($list) {
    # 0.40.2: arrow keys move the highlight, Enter picks. Without a real console: type a number or name.
    Write-Host ""
    Write-Host "Which VM is the FatBox test VM?  (Up/Down to move, Enter to pick, Esc to stop)" -ForegroundColor Cyan
    $interactive = $true
    try { if ([Console]::IsInputRedirected) { $interactive = $false } } catch { $interactive = $false }
    if ($interactive) {
        try {
            $sel = 0
            for ($i = 0; $i -lt $list.Count; $i++) { Write-Host "" }
            $top = [Console]::CursorTop - $list.Count
            [Console]::CursorVisible = $false
            while ($true) {
                for ($i = 0; $i -lt $list.Count; $i++) {
                    [Console]::SetCursorPosition(0, $top + $i)
                    $line = ("  {0} {1}" -f $(if ($i -eq $sel) { ">" } else { " " }), $list[$i]).PadRight([Console]::WindowWidth - 1)
                    if ($i -eq $sel) { Write-Host $line -ForegroundColor Black -BackgroundColor Cyan -NoNewline }
                    else { Write-Host $line -NoNewline }
                }
                [Console]::SetCursorPosition(0, $top + $list.Count)
                $k = [Console]::ReadKey($true)
                switch ($k.Key) {
                    "UpArrow"   { $sel = ($sel - 1 + $list.Count) % $list.Count }
                    "DownArrow" { $sel = ($sel + 1) % $list.Count }
                    "Enter"     { [Console]::CursorVisible = $true; Write-Host "==> test VM: $($list[$sel])" -ForegroundColor Cyan; return $list[$sel] }
                    "Escape"    { [Console]::CursorVisible = $true; throw "Stopped: no VM picked." }
                }
            }
        } catch [System.IO.IOException] {
            [Console]::CursorVisible = $true   # no real console after all (e.g. ISE): fall back to typing
        } catch [System.InvalidOperationException] {
            [Console]::CursorVisible = $true
        }
    }
    for ($i = 0; $i -lt $list.Count; $i++) { Write-Host ("  {0}. {1}" -f ($i + 1), $list[$i]) }
    $n = (Read-Host "Type its number or exact name").Trim()
    if ($n -match '^\d+$' -and [int]$n -ge 1 -and [int]$n -le $list.Count) { return $list[[int]$n - 1] }
    if ($list -contains $n) { return $n }
    throw "No VM '$n': type its number (1-$($list.Count)) or its exact name."
}

$root = Split-Path -Parent $PSScriptRoot
$prov = Join-Path $root "scripts\lab\provision-vm.ps1"
if (-not (Test-Path (Join-Path $root "fatbox\host\__main__.py")) -or -not (Test-Path $prov)) {
    throw "Run this from the FatBox folder you cloned: .\scripts\setup-host.ps1"
}
$want = (Select-String -Path (Join-Path $root "fatbox\__init__.py") -Pattern '__version__ = "([0-9.]+)"').Matches[0].Groups[1].Value
if ($GuestUser -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$') { throw "-GuestUser must be a simple Windows user name." }
if (-not (Test-Path $VBoxManage)) { throw "VirtualBox not found at $VBoxManage (install VirtualBox 7, or use -VBoxManage)." }
$vbv = (& $VBoxManage --version | Out-String).Trim()
if ($vbv -notmatch '^7\.') { throw "FatBox needs VirtualBox 7 (this PC has $vbv)." }

# 1. Python 3.11+ on the host (FatBox's host side is standard library only)
function Find-Python {
    foreach ($c in @((Get-Command py.exe -ErrorAction SilentlyContinue), (Get-Command python.exe -ErrorAction SilentlyContinue))) {
        if (-not $c -or $c.Source -match 'WindowsApps') { continue }
        $exe = if ($c.Name -eq "py.exe") { (Quiet $c.Source -3 -c "import sys; print(sys.executable)").Trim() } else { $c.Source }
        if ($exe -and (Test-Path $exe)) {
            & $exe -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
            if ($LASTEXITCODE -eq 0) { return $exe }
        }
    }
    $own = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"
    if (Test-Path $own) { return $own }
    return $null
}
$py = Find-Python
if (-not $py) {
    Say "Python 3.11+ not found: installing Python 3.13 for $env:USERNAME"
    $pi = Join-Path $env:TEMP "python-3.13.9-amd64.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe" -OutFile $pi -UseBasicParsing -TimeoutSec 900
    $sig = Get-AuthenticodeSignature $pi
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Python Software Foundation") {
        Remove-Item $pi -Force; throw "the Python installer is not validly signed; not running it"
    }
    $p = Start-Process $pi -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0" -Wait -PassThru
    Remove-Item $pi -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -ne 0) { throw "Python install failed ($($p.ExitCode))" }
    $py = Find-Python
    if (-not $py) { throw "Python was installed but not found; open a new PowerShell and run this again." }
}
$vpy = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $vpy)) {
    Say "FatBox host: .venv in $root"
    & $py -m venv (Join-Path $root ".venv")
    if ($LASTEXITCODE -ne 0) { throw "python -m venv failed" }
}

# 2. The VM
$vms = @(& $VBoxManage list vms | ForEach-Object { if ($_ -match '^"(.*)" \{[0-9a-f-]+\}$') { $Matches[1] } })
if (-not $vms) { throw "VirtualBox has no VMs for $env:USERNAME. Create a Windows 10/11 VM first (install Windows in it, nothing else)." }
if (-not $Vm) {
    $Vm = Select-Vm $vms
}
if ($vms -notcontains $Vm) { throw "VirtualBox has no VM named '$Vm'." }
if ($Vm -match '["'']') { throw "Rename the VM in VirtualBox: its name may not contain quotes." }
$info = & $VBoxManage showvminfo $Vm --machinereadable
if (-not ($info -match '^VMState="poweroff"') -and -not ($info -match '^VMState="aborted"')) {
    throw "Shut '$Vm' down first (VirtualBox must show it as Powered Off), then run this again."
}
if (-not ($info -match '^ostype="Windows')) { Write-Warning "'$Vm' does not look like a Windows VM; FatBox's test VM must run Windows 10/11." }

$secKey = Read-Host "MalwareBazaar API key (free at https://auth.abuse.ch/; Enter = set it later)" -AsSecureString
$mbKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secKey)).Trim()
if ($mbKey -and $mbKey -notmatch '^[A-Za-z0-9]{16,128}$') { throw "That doesn't look like a MalwareBazaar key (letters and digits)." }

# 3. Password, host.toml (one PC layout)
$home_ = Join-Path $env:APPDATA "fatbox-host"
New-Item -ItemType Directory -Force -Path $home_ | Out-Null
$abc = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = -join ($bytes | ForEach-Object { $abc[$_ % $abc.Length] })
$pwFile = Join-Path $home_ "guest.pw"
if ("$pwFile$VBoxManage" -match "'") { throw "Paths with an apostrophe (') are not supported: $pwFile" }
if (Test-Path $pwFile) {
    icacls $pwFile /grant:r "$($env:USERNAME):F" | Out-Null
    $pwBak = "$pwFile.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")   # 0.40.2: an older setup's password is kept
    Copy-Item $pwFile $pwBak
    icacls $pwBak /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
    Say "old guest password kept as $pwBak"
}
[IO.File]::WriteAllText($pwFile, $password, (New-Object Text.UTF8Encoding $false))
icacls $pwFile /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
Say "guest password for '$GuestUser' saved in $pwFile (only $env:USERNAME can read it)"

$toml = Join-Path $home_ "host.toml"
if (Test-Path $toml) {
    $bak = "$toml.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Copy-Item $toml $bak
    Say "old host.toml kept as $bak"
}
$body = @"
# FatBox host controller settings, written by scripts\setup-host.ps1. Keep this file OUT of the git repo.
vm = '$Vm'
guest_user = '$GuestUser'
password_file = '$pwFile'
guest_python = 'C:\Python313\python.exe'
guest_dir = 'C:\fatbox'
vboxmanage = '$VBoxManage'
sample_time_s = 60
capa_time_s = 120
port = 8790
clean_snapshot = ""
"@
[IO.File]::WriteAllText($toml, $body.Replace("`r`n", "`n") + "`n", (New-Object Text.UTF8Encoding $false))
$labJson = Join-Path $home_ "lab.json"   # the GUI's lab layout wins over host.toml: set it to One PC too
[IO.File]::WriteAllText($labJson, '{"layout": "one-pc", "address": "", "login": "", "port": 22}', (New-Object Text.UTF8Encoding $false))
Say "host.toml written for VM '$Vm' (One PC layout)"

# 4. Safe VM settings (VM off)
Say "safe VM settings: NAT, no access to this PC's own services, no clipboard, drag-and-drop, shared folders, USB, audio or 3D"
foreach ($m in ($info | Select-String '^SharedFolderNameMachineMapping\d+="(.*)"')) {
    VBM sharedfolder remove $Vm --name $m.Matches.Groups[1].Value
}
VBM modifyvm $Vm --nic1 nat --cableconnected1 off --nat-localhostreachable1 off --clipboard-mode disabled `
    --drag-and-drop disabled --usb-ohci off --usb-ehci off --usb-xhci off --audio-enabled off --accelerate-3d off

# 5. The setup disc: Setup.cmd + provision-vm.ps1 + a one-off settings file (password, key, repo)
$repo = (Quiet git -C $root remote get-url origin).Trim() -replace '\.git$', ''
if ($repo -notmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw "Can't tell which GitHub repo this FatBox came from (git remote get-url origin: '$repo')." }
# 0.42.0: no token, ever. The VM gets THIS PC's FatBox code on the setup disc (a git bundle) and later from
# Update VM the same way; it never logs in to GitHub, so a private repo works like a public one.
# 0.40.3: the Guest Additions disc by its file path (VBoxManage's "additions" keyword fails when VirtualBox has no default set)
$gaIso = ((& $VBoxManage list systemproperties | Select-String '^Default Guest Additions ISO:\s+(.+)$').Matches |
    ForEach-Object { $_.Groups[1].Value.Trim() } | Select-Object -First 1)
if (-not $gaIso -or -not (Test-Path $gaIso)) { $gaIso = Join-Path (Split-Path -Parent $VBoxManage) "VBoxGuestAdditions.iso" }
if (-not (Test-Path $gaIso)) { throw "VirtualBox's Guest Additions disc was not found ($gaIso). Repair or reinstall VirtualBox, then run this again." }
$stage = Join-Path $home_ "setup-disc"
$iso = Join-Path $home_ "fatbox-setup.iso"
$ctl = "FatBox setup"
$ownCtl = $true          # 0.40.2: a VM has at most one SATA controller; reuse it when it exists
$discPorts = @(0, 1)
$started = $false
$ok = $false
try {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Copy-Item $prov (Join-Path $stage "provision-vm.ps1")
    Quiet git -C $root bundle create --quiet (Join-Path $stage "fatbox.bundle") HEAD | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $stage "fatbox.bundle"))) { throw "Could not pack this PC's FatBox code (git bundle in $root)." }
    $cmd = "@echo off`r`necho FatBox setup: click Yes to let it set up this VM.`r`n" +
           "powershell -NoProfile -ExecutionPolicy Bypass -Command `"Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File %~dp0provision-vm.ps1 -FromDisc'`"`r`n"
    [IO.File]::WriteAllText((Join-Path $stage "Setup.cmd"), $cmd, (New-Object Text.ASCIIEncoding))
    $cfg = [ordered]@{ user = $GuestUser; password = $password; mb_api_key = $mbKey; repo = $repo } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $stage "fatbox-setup.json"), $cfg, (New-Object Text.UTF8Encoding $false))
    $password = $null; $mbKey = $null; $cfg = $null

    if (-not ("FatBoxIso" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class FatBoxIso {
    public static void Save(object image, string path) {
        IStream s = (IStream)image;
        byte[] buf = new byte[65536];
        IntPtr read = Marshal.AllocHGlobal(4);
        try {
            using (FileStream fs = File.Create(path)) {
                while (true) {
                    s.Read(buf, buf.Length, read);
                    int n = Marshal.ReadInt32(read);
                    if (n <= 0) break;
                    fs.Write(buf, 0, n);
                }
            }
        } finally { Marshal.FreeHGlobal(read); }
    }
}
'@
    }
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage    # built into Windows: no extra tools
    $fsi.FileSystemsToCreate = 3                                  # ISO 9660 + Joliet (long file names)
    $fsi.VolumeName = "FATBOX"
    $fsi.Root.AddTree($stage, $false)
    [FatBoxIso]::Save($fsi.CreateResultImage().ImageStream, $iso)
    Remove-Item $stage -Recurse -Force
    icacls $iso /inheritance:r /grant:r "$($env:USERNAME):F" "SYSTEM:F" | Out-Null

    # The VM's own SATA controller (VirtualBox allows only one), else a new one just for the setup discs
    $sata = $null
    foreach ($m in ($info | Select-String '^storagecontrollername(\d+)="(.*)"')) {
        $i = $m.Matches.Groups[1].Value
        if ($info -match "^storagecontrollertype$i=`"IntelAhci`"") {
            $sata = $m.Matches.Groups[2].Value
            $ports = [int](($info | Select-String "^storagecontrollerportcount$i=`"(\d+)`"").Matches.Groups[1].Value)
        }
    }
    if ($sata -and $sata -ne $ctl) {
        $ownCtl = $false
        $ctl = $sata
        $used = @($info | Select-String ('^"' + [regex]::Escape($ctl) + '-(\d+)-0"="(?!none")') | ForEach-Object { [int]$_.Matches.Groups[1].Value })
        $discPorts = @(0..29 | Where-Object { $used -notcontains $_ } | Select-Object -First 2)
        if ($discPorts.Count -lt 2) { throw "'$ctl' in '$Vm' has no 2 free ports for the setup discs." }
        $need = ($discPorts | Measure-Object -Maximum).Maximum + 1
        if ($need -gt $ports) { VBM storagectl $Vm --name $ctl --portcount $need }
        Say "setup discs go on '$ctl' ports $($discPorts -join ' and ')"
    } elseif (-not $sata) {
        VBM storagectl $Vm --name $ctl --add sata --controller IntelAhci --portcount 2
    }
    VBM storageattach $Vm --storagectl $ctl --port $discPorts[0] --device 0 --type dvddrive --medium $iso
    VBM storageattach $Vm --storagectl $ctl --port $discPorts[1] --device 0 --type dvddrive --medium $gaIso

    # 6. Network in only for the setup (INV-7), then start the VM for the client
    VBM modifyvm $Vm --cableconnected1 on
    Say "starting '$Vm' with the network plugged in (only for this setup)"
    VBM startvm $Vm --type gui
    $started = $true
    Write-Host ""
    Write-Host "  In the VM window:" -ForegroundColor Yellow
    Write-Host "   1. Sign in to Windows." -ForegroundColor Yellow
    Write-Host "   2. File Explorer > This PC > the FATBOX disc > double-click Setup.cmd > Yes." -ForegroundColor Yellow
    Write-Host "  It installs everything (15-40 minutes) and may restart the VM once. Keep this window open." -ForegroundColor Yellow
    Write-Host ""

    # 7. Wait until FatBox answers in the VM as the 'fatbox' user, with the host's own version
    $deadline = (Get-Date).AddMinutes($WaitMin)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 20
        $out = Quiet $VBoxManage guestcontrol $Vm run --username $GuestUser --passwordfile $pwFile --timeout 60000 `
            --wait-stdout '--' C:\Windows\System32\cmd.exe /c type C:\fatbox\setup-done.txt
        if ($LASTEXITCODE -eq 0 -and $out.Trim() -eq "FatBox $want") { $ready = $true; break }
        if ($LASTEXITCODE -eq 0 -and $out.Trim() -match '^FatBox ') { throw "The VM has $($out.Trim()), the host has FatBox ${want}: update this folder (git pull) and run this again." }
        Write-Host "   ...waiting for the VM ($(Get-Date -Format HH:mm))"
    }
    if (-not $ready) { throw "FatBox did not answer in the VM within $WaitMin minutes. Look at the setup window in the VM for the reason, fix it, and run this again." }
    # A restart the VM scheduled (Guest Additions just installed): let it finish, then check once more
    Start-Sleep -Seconds 30
    for ($i = 0; $i -lt 45; $i++) {
        Quiet $VBoxManage guestcontrol $Vm run --username $GuestUser --passwordfile $pwFile --timeout 60000 `
            --wait-stdout '--' C:\Windows\System32\cmd.exe /c ver | Out-Null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 20
    }
    Say "FatBox $want answers in the VM"
    $ok = $true
} finally {
    $ErrorActionPreference = "Continue"   # every cleanup step runs, even if one fails
    # ALWAYS: network out (INV-7), discs out, the setup disc file (it held the password and key) deleted
    $state = (& $VBoxManage showvminfo $Vm --machinereadable | Select-String '^VMState="(.*)"').Matches.Groups[1].Value
    if ($state -eq "running") { & $VBoxManage controlvm $Vm setlinkstate1 off }
    Quiet $VBoxManage modifyvm $Vm --cableconnected1 off | Out-Null
    foreach ($port in $discPorts) {
        if ($state -eq "running") {   # a running VM keeps the empty drives until it is off
            Quiet $VBoxManage storageattach $Vm --storagectl $ctl --port $port --device 0 --type dvddrive --medium emptydrive --forceunmount | Out-Null
        } elseif (-not $ownCtl) {     # the VM's own controller: take out only the drives this setup added
            Quiet $VBoxManage storageattach $Vm --storagectl $ctl --port $port --device 0 --medium none | Out-Null
        }
    }
    if ($ownCtl -and $state -ne "running") { Quiet $VBoxManage storagectl $Vm --name $ctl --remove | Out-Null }
    Quiet $VBoxManage closemedium dvd $iso | Out-Null
    Remove-Item $iso, $stage -Recurse -Force -ErrorAction SilentlyContinue
    $info2 = & $VBoxManage showvminfo $Vm --machinereadable
    if ($info2 -match '^cableconnected1="on"') { Write-Warning "The VM's network may still be plugged in: VirtualBox > '$Vm' > Settings > Network > untick Cable Connected." }
    elseif ($ok) { Say "network unplugged, setup discs removed" }
    else { Say "setup stopped: network unplugged, setup discs removed (the reason is below). Fix it and run this script again." }
    if (Test-Path $iso) { Write-Warning "Delete $iso by hand: it holds the VM password." }
}

# Desktop shortcut and a last check
Push-Location $root
& $vpy -m fatbox.host shortcut
& $vpy -m fatbox.host check
Pop-Location
Write-Host ""
Say "Done. Open 'FatBox Host' on the desktop -> Snapshots -> Make clean snapshot (the VM stays running for it)."
