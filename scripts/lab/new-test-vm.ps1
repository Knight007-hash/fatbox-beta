<#
FatBox: build a fresh test VM from a Windows ISO (T-19). No existing VM (FlareVM or other) is needed.

Run on the PC whose VirtualBox will hold the test VM (this PC in a one-PC lab, the test PC in a two-machine
lab), in a normal PowerShell as the user who will own the VM:

  powershell -ExecutionPolicy Bypass -File .\new-test-vm.ps1 -Iso D:\Win11_Eval.iso

It takes 30-90 minutes and needs no clicks after the start. What it does:
 1. Creates the VM with safe settings: NAT network with the cable unplugged, clipboard and drag-and-drop off,
    no shared folders, no USB, no audio, 3D off, EFI + TPM 2.0 (Windows 11 needs them).
 2. Installs Windows unattended (VirtualBox's own installer) with Guest Additions.
 3. Plugs the cable in, copies provision-vm.ps1 in and runs it: Python 3.13, Git, the VC++ runtime, FatBox
    (VM side, pinned libraries), Defender exclusion, Windows Update and SmartScreen off.
 4. Unplugs the cable again and prints the values for host.toml (or lab-setup.ps1).
Then open the FatBox GUI and click "Make clean snapshot": that finishes the VM.

The guest password goes to VirtualBox through a file, never on a command line. 0.42.0: no GitHub token: the VM
gets this PC's FatBox code as a git bundle copied in over guest control, and never logs in to GitHub.

Mid-range default: 4 CPUs, 8 GB RAM, 80 GB disk (grows as used). Change with -Cpus / -MemoryMB / -DiskGB.
#>
param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [string]$Name = "fatbox-test",
    [int]$Cpus = 4,
    [int]$MemoryMB = 8192,
    [int]$DiskGB = 80,
    [string]$GuestUser = "analyst",
    [string]$PasswordFile = "",                 # where to keep the guest password (default: next to the VM)
    [int]$ImageIndex = 0,                       # Windows edition inside the ISO; 0 = VirtualBox picks
    [string]$Repo = "https://github.com/Knight007-hash/fatbox-beta.git",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    [int]$InstallTimeoutMin = 120
)
$ErrorActionPreference = "Stop"
function Say($t) { Write-Host "==> $t" -ForegroundColor Cyan }
function VBM {
    & $VBoxManage @args
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args[0]) failed (exit $LASTEXITCODE)" }
}

if (-not (Test-Path $VBoxManage)) { throw "VBoxManage not found at $VBoxManage (install VirtualBox 7.x or use -VBoxManage)." }
if (-not (Test-Path $Iso)) { throw "ISO not found: $Iso" }
if ($Name -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw "-Name may use letters, digits, . _ - only." }
if ($GuestUser -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$') { throw "-GuestUser must be a simple Windows user name." }
if ($Cpus -lt 2 -or $MemoryMB -lt 4096 -or $DiskGB -lt 64) { throw "The VM needs at least 2 CPUs, 4096 MB RAM and 64 GB disk." }
& $VBoxManage showvminfo $Name *> $null
if ($LASTEXITCODE -eq 0) { throw "A VM named '$Name' already exists. Pick another -Name or delete it in VirtualBox." }

$pw1 = Read-Host "New password for '$GuestUser' inside the VM" -AsSecureString
$pw2 = Read-Host "Same password again" -AsSecureString
$p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1))
$p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2))
if ($p1 -ne $p2 -or $p1.Length -lt 8) { throw "Passwords differ or are shorter than 8 characters." }

# 1. The VM
Say "Creating VM '$Name' ($Cpus CPUs, $MemoryMB MB, $DiskGB GB)"
$ostype = "Windows11_64"
VBM createvm --name $Name --ostype $ostype --register
$folder = Split-Path ((& $VBoxManage showvminfo $Name --machinereadable | Select-String '^CfgFile=') -replace '^CfgFile="(.*)"$', '$1')
if (-not $PasswordFile) { $PasswordFile = Join-Path $folder "guest.pw" }
[IO.File]::WriteAllText($PasswordFile, $p1, (New-Object Text.UTF8Encoding $false))
$p1 = $p2 = $null
icacls $PasswordFile /inheritance:r /grant:r "$($env:USERNAME):F" "SYSTEM:F" | Out-Null

VBM modifyvm $Name --cpus $Cpus --memory $MemoryMB --vram 128 --graphicscontroller vboxsvga `
    --firmware efi --tpm-type 2.0 --nic1 nat --cableconnected1 off `
    --clipboard-mode disabled --drag-and-drop disabled --usb-ohci off --usb-ehci off --usb-xhci off `
    --audio-enabled off --accelerate-3d off --ioapic on
$disk = Join-Path $folder "$Name.vdi"
VBM createmedium disk --filename $disk --size ($DiskGB * 1024) --format VDI
VBM storagectl $Name --name SATA --add sata --controller IntelAhci --portcount 2
VBM storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk

# 2. Unattended Windows install. The post-install command runs as SYSTEM at the end of setup: it lets the
#    guest user's FatBox commands run with full admin rights (UAC off; samples are never run, INV-3).
Say "Installing Windows unattended (no clicks needed; 20-60 minutes)"
$ua = @("unattended", "install", $Name, "--iso=$Iso", "--user=$GuestUser", "--password-file=$PasswordFile",
        "--full-user-name=$GuestUser", "--install-additions", "--locale=en_US", "--country=US",
        "--time-zone=UTC", "--hostname=$Name.local",
        "--post-install-command=cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f",
        "--start-vm=headless")
if ($ImageIndex -gt 0) { $ua += "--image-index=$ImageIndex" }
VBM @ua

$deadline = (Get-Date).AddMinutes($InstallTimeoutMin)
$ready = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 30
    $info = & $VBoxManage showvminfo $Name --machinereadable
    $level = ($info | Select-String '^GuestAdditionsRunLevel=(\d)').Matches.Groups[1].Value
    if ($level -and [int]$level -ge 2) {
        & $VBoxManage guestcontrol $Name run --username $GuestUser --passwordfile $PasswordFile `
            --timeout 30000 --wait-stdout -- C:\Windows\System32\cmd.exe /c ver *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    Write-Host "   ...still installing ($(Get-Date -Format HH:mm))"
}
if (-not $ready) { throw "Windows did not finish installing within $InstallTimeoutMin minutes. Open the VM in VirtualBox to see why." }

# Reboot once so the UAC change applies, then wait for guest control again.
Say "Restarting the VM once (applies the admin setting)"
VBM controlvm $Name acpipowerbutton
for ($i = 0; $i -lt 40; $i++) { Start-Sleep 5; if ((& $VBoxManage showvminfo $Name --machinereadable) -match 'VMState="poweroff"') { break } }
VBM startvm $Name --type headless
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep 10
    & $VBoxManage guestcontrol $Name run --username $GuestUser --passwordfile $PasswordFile `
        --timeout 30000 --wait-stdout -- C:\Windows\System32\cmd.exe /c ver *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
}
if (-not $ready) { throw "The VM did not come back after the restart." }

# 3. Provision (network on only for this)
Say "Provisioning: Python, Git, VC++ runtime, FatBox (network on only now)"
$tmp = Join-Path $env:TEMP "fatbox.bundle"
try {
    & git -C (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) bundle create --quiet $tmp HEAD
    if ($LASTEXITCODE -ne 0) { throw "Could not pack FatBox's code: run this from scripts\lab inside a FatBox git folder." }
    VBM guestcontrol $Name mkdir --username $GuestUser --passwordfile $PasswordFile --parents C:\fatbox-setup
    VBM guestcontrol $Name copyto --username $GuestUser --passwordfile $PasswordFile `
        --target-directory C:\fatbox-setup\ (Join-Path $PSScriptRoot "provision-vm.ps1") $tmp
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
VBM controlvm $Name setlinkstate1 on
try {
    & $VBoxManage guestcontrol $Name run --username $GuestUser --passwordfile $PasswordFile `
        --timeout 3600000 --wait-stdout --wait-stderr --profile `
        -- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File C:\fatbox-setup\provision-vm.ps1 -Bundle C:\fatbox-setup\fatbox.bundle -Repo $Repo -NoPrompt
    $code = $LASTEXITCODE
} finally {
    # 4. Cable out, whatever happened (INV-7)
    & $VBoxManage controlvm $Name setlinkstate1 off
    & $VBoxManage modifyvm $Name --cableconnected1 off 2>$null
}
if ($code -ne 0) { throw "Provisioning failed in the VM (exit $code): see the lines above." }

Say "Done. Network unplugged. Values for FatBox:"
Write-Host @"

  host.toml (one PC)                       lab-setup.ps1 (two machines)
  vm = "$Name"                             -Vm "$Name"
  guest_user = "$GuestUser"                -GuestUser "$GuestUser"
  guest_python = 'C:\Python313\python.exe' -GuestPython "C:\Python313\python.exe"
  guest_dir = 'C:\fatbox'                  (guest_dir goes in host.toml on the GUI PC)
  password_file = '$PasswordFile'

Last step: open the FatBox GUI, then Snapshots -> Make clean snapshot.
"@
