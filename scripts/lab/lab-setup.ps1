<#
FatBox lab setup for the TEST PC: the computer whose VirtualBox holds the test VM (T-19).
Run once, in PowerShell "Run as administrator", logged in as the Windows user who owns the test VM
(an administrator account), with Python 3.11+ installed:

  powershell -ExecutionPolicy Bypass -File .\lab-setup.ps1 -HostAddress 10.99.0.1 -PublicKey "ssh-ed25519 AAAA... fatbox-host"

-HostAddress  the FatBox host's IP (main PC, or the host VM). Only it may connect.
-PublicKey    the line 'python -m fatbox.host lab pair' printed on the host.

What it does (each step says so as it runs):
 1. Turns on Windows' built-in OpenSSH Server, key logins only (passwords off).
 2. Puts fatbox_gate.py + fatbox_gate.toml in C:\fatbox-lab (only you, Administrators and SYSTEM can read it).
 3. Saves the test VM's guest password in C:\fatbox-lab\guest.pw (asked here, never sent over the network).
 4. Lets the host's key run ONLY the gate: no shell, no forwarding, only from -HostAddress.
 5. Firewall: SSH in only from -HostAddress; the test VM's process may not reach private networks
    (the host, your home LAN) - so a hacked VM can't, even while fetching.
 6. Sets the VM's NAT DNS to the host resolver, so fetching still works with that block.
 7. Prints this PC's SSH fingerprint: compare it with what 'lab check' shows on the host.
#>
param(
    [Parameter(Mandatory = $true)][string]$HostAddress,
    [Parameter(Mandatory = $true)][string]$PublicKey,
    [string]$Vm = "fatbox-vm",
    [string]$GuestUser = "analyst",
    [string]$GuestPython = "C:\Python313\python.exe",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    [string]$Python = "",
    [string]$LabDir = "C:\fatbox-lab"
)
$ErrorActionPreference = "Stop"

function Say($t) { Write-Host "==> $t" -ForegroundColor Cyan }

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal $me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this in PowerShell 'Run as administrator'." }
if ($LabDir -notmatch '^[A-Za-z]:\\[A-Za-z0-9_\\-]+$') { throw "LabDir must be a path without spaces, like C:\fatbox-lab" }
if ($HostAddress -notmatch '^[0-9A-Fa-f.:]{2,45}$') { throw "HostAddress must be an IP address, like 10.99.0.1" }
if ($PublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]{60,100}( [A-Za-z0-9._@-]{0,64})?$') {
    throw "PublicKey must be the one line 'python -m fatbox.host lab pair' printed (starts with ssh-ed25519)."
}
if (-not (Test-Path $VBoxManage)) { throw "VBoxManage not found at $VBoxManage (use -VBoxManage)." }
& $VBoxManage showvminfo $Vm --machinereadable *> $null
if ($LASTEXITCODE -ne 0) { throw "VirtualBox has no VM named '$Vm' for user $env:USERNAME (use -Vm, and run as the VM's owner)." }
if (-not $Python) { $Python = (Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch 'WindowsApps' } | Select-Object -First 1).Source }
if (-not $Python -or -not (Test-Path $Python)) { throw "Python 3.11+ not found on this PC: install it from python.org, or pass -Python C:\path\python.exe" }
& $Python -c "import sys, tomllib; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) { throw "$Python is older than 3.11." }

# 1. OpenSSH Server, key logins only
Say "OpenSSH Server: install and start (key logins only)"
$cap = Get-WindowsCapability -Online -Name "OpenSSH.Server*" | Select-Object -First 1
if ($cap.State -ne "Installed") { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
Set-Service sshd -StartupType Automatic
Start-Service sshd
$cfgPath = "$env:ProgramData\ssh\sshd_config"
$cfg = Get-Content $cfgPath -Raw
if ($cfg -notmatch '(?m)^PasswordAuthentication no') {
    Copy-Item $cfgPath "$cfgPath.fatbox-backup" -Force
    $cfg = $cfg -replace '(?m)^#?\s*PasswordAuthentication .*$', ''
    $cfg = "PasswordAuthentication no`r`nAllowTcpForwarding no`r`nPermitTunnel no`r`n" + $cfg
    Set-Content -Path $cfgPath -Value $cfg -Encoding ascii
}

# 2. The gate
Say "Gate: $LabDir"
New-Item -ItemType Directory -Force -Path $LabDir | Out-Null
Copy-Item (Join-Path $PSScriptRoot "fatbox_gate.py") (Join-Path $LabDir "fatbox_gate.py") -Force
$pw = Join-Path $LabDir "guest.pw"
$toml = @"
# FatBox lab gate settings (T-19). The host can only run VirtualBox commands for this VM.
vm = '$Vm'
vboxmanage = '$VBoxManage'
guest_user = '$GuestUser'
guest_python = '$GuestPython'
password_file = '$pw'
"@
# UTF-8 without a BOM (Python's TOML reader refuses one)
[IO.File]::WriteAllText((Join-Path $LabDir "fatbox_gate.toml"), $toml, (New-Object Text.UTF8Encoding $false))
icacls $LabDir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null

# 3. Guest password (stays on this PC)
if (-not (Test-Path $pw)) {
    $sec = Read-Host "Password of '$GuestUser' inside the test VM" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    Set-Content -Path $pw -Value $plain -Encoding ascii -NoNewline
    $plain = $null
}

# 4. The host's key may run only the gate
Say "Key: only the gate, only from $HostAddress"
# sshd hands the forced command to cmd.exe, which mangles nested quotes: so authorized_keys names a .cmd file
# with no spaces in its path, and the .cmd file quotes the paths itself.
$gateCmdFile = Join-Path $LabDir "gate.cmd"
Set-Content -Path $gateCmdFile -Encoding ascii -Value @("@echo off", "`"$Python`" -I `"$(Join-Path $LabDir 'fatbox_gate.py')`"", "exit /b %errorlevel%")
$gateCmd = $gateCmdFile
$line = "from=`"$HostAddress`",command=`"$gateCmd`",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc $PublicKey"
# This runs elevated as the VM's owner, so that account is an administrator: Windows' sshd reads the keys of
# administrators from ProgramData, never from the user's own .ssh folder.
$ak = "$env:ProgramData\ssh\administrators_authorized_keys"
$keep = @()
if (Test-Path $ak) { $keep = Get-Content $ak | Where-Object { $_ -notmatch 'fatbox-lab|gate\.cmd' } }
Set-Content -Path $ak -Value (@($keep) + $line) -Encoding ascii
icacls $ak /inheritance:r /grant "Administrators:F" "SYSTEM:F" | Out-Null

# 5. Firewall
Say "Firewall: SSH only from $HostAddress; the VM may not reach private networks"
Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Disable-NetFirewallRule
Get-NetFirewallRule -DisplayName "FatBox lab*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "FatBox lab SSH from host" -Direction Inbound -Protocol TCP -LocalPort 22 `
    -RemoteAddress $HostAddress -Action Allow | Out-Null
$vmExe = Join-Path (Split-Path $VBoxManage) "VirtualBoxVM.exe"
New-NetFirewallRule -DisplayName "FatBox lab VM no private networks" -Direction Outbound -Program $vmExe `
    -RemoteAddress @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10") `
    -Action Block | Out-Null

# 6. NAT DNS through this PC's resolver (the block above would stop DNS to a LAN router)
Say "VM NAT DNS: host resolver"
& $VBoxManage modifyvm $Vm --natdnshostresolver1 on 2>$null
if ($LASTEXITCODE -ne 0) { Write-Warning "VM is running: shut it down and run:  & '$VBoxManage' modifyvm '$Vm' --natdnshostresolver1 on" }

Restart-Service sshd

# 7. Fingerprint to compare on the host
Say "Done. This PC's SSH fingerprint (compare with 'python -m fatbox.host lab check' on the host):"
& "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe" -l -f "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
Write-Host "Keep this PC signed in as $env:USERNAME with VirtualBox open while FatBox works."
