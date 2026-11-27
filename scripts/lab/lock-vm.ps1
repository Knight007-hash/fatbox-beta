<#
FatBox: lock down an existing test VM's VirtualBox settings (T-19, "Prepare existing VM").
Run on the PC that runs VirtualBox, as the VM's owner, with the VM shut down:

  powershell -ExecutionPolicy Bypass -File .\lock-vm.ps1 -Vm "my test vm"

Sets what SPEC requires (INV-6, INV-7): network on NAT with the cable unplugged (FatBox plugs it in only to
fetch or update), clipboard and drag-and-drop off, shared folders removed, USB, audio and 3D off.
new-test-vm.ps1 makes a VM like this from the start; this is for a VM you made yourself.
#>
param(
    [Parameter(Mandatory = $true)][string]$Vm,
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $VBoxManage)) { throw "VBoxManage not found at $VBoxManage (use -VBoxManage)." }
$info = & $VBoxManage showvminfo $Vm --machinereadable
if ($LASTEXITCODE -ne 0) { throw "VirtualBox has no VM named '$Vm' for user $env:USERNAME." }
if ($info -notmatch '^VMState="poweroff"') { throw "Shut the VM down first (VirtualBox shows it as Powered Off)." }

foreach ($m in ($info | Select-String '^SharedFolderNameMachineMapping\d+="(.*)"')) {
    $name = $m.Matches.Groups[1].Value
    & $VBoxManage sharedfolder remove $Vm --name $name
    Write-Host "removed shared folder '$name'"
}
& $VBoxManage modifyvm $Vm --nic1 nat --cableconnected1 off --clipboard-mode disabled --drag-and-drop disabled `
    --usb-ohci off --usb-ehci off --usb-xhci off --audio-enabled off --accelerate-3d off
if ($LASTEXITCODE -ne 0) { throw "VBoxManage modifyvm failed." }
Write-Host "Locked: NAT with the cable out, no clipboard, drag-and-drop, shared folders, USB, audio or 3D."
Write-Host "Next: start the VM, then FatBox GUI -> Snapshots -> Make clean snapshot."
