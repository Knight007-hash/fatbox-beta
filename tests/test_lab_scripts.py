"""T-19 Build test VM: the PowerShell scripts can't run in CI, so their safety promises are checked as text."""
from pathlib import Path

LAB = Path(__file__).resolve().parents[1] / "scripts" / "lab"
NEW = (LAB / "new-test-vm.ps1").read_text(encoding="utf-8")
PROV = (LAB / "provision-vm.ps1").read_text(encoding="utf-8")
LOCK = (LAB / "lock-vm.ps1").read_text(encoding="utf-8")


def test_new_vm_is_isolated_by_default():
    for setting in ("--cableconnected1 off", "--clipboard-mode disabled", "--drag-and-drop disabled",
                    "--usb-xhci off", "--audio-enabled off", "--accelerate-3d off", "--nic1 nat"):
        assert setting in NEW, setting                      # INV-6, INV-7, T-10 checklist
    assert "sharedfolder" not in NEW


def test_secrets_never_on_a_command_line():
    assert "--password-file=" in NEW and "--password=" not in NEW
    assert "-Token" not in NEW and "Read-Host \"Read-only GitHub token" not in NEW   # 0.42.0: no token at all
    assert "Remove-Item $tmp" in NEW                       # the host-side bundle copy is deleted
    assert "Remove-Item $TokenFile" in PROV                # by hand (c) only
    assert "extraheader" in PROV and "x-access-token:$token@" not in PROV   # never stored in .git\config


def test_network_only_while_provisioning():
    on = NEW.index("setlinkstate1 on")
    off = NEW.index("setlinkstate1 off")
    assert on < off and "finally" in NEW[on:off]             # unplugged even when provisioning fails


def test_installers_are_signature_checked_before_running():
    for signer in ("Microsoft Corporation", "Python Software Foundation", "Johannes Schindelin"):
        assert signer in PROV
    assert PROV.count("Get-Signed ") == 3
    assert "--require-hashes" in PROV                       # pinned FatBox libraries


def test_mid_range_defaults():
    assert "[int]$Cpus = 4" in NEW and "[int]$MemoryMB = 8192" in NEW


def test_existing_vm_path():
    assert '[string]$TokenFile = ""' in PROV and "Read-Host" in PROV      # runs on its own (asks only for the MalwareBazaar key)
    assert "VBoxService" in PROV                                          # Guest Additions are required
    for setting in ("--cableconnected1 off", "--clipboard-mode disabled", "--drag-and-drop disabled",
                    "--usb-xhci off", "--audio-enabled off", "sharedfolder remove"):
        assert setting in LOCK, setting


HOSTSETUP = (LAB.parent / "setup-host.ps1").read_text(encoding="utf-8")


def test_one_pc_setup_unplugs_and_cleans_up_always():                  # T-23, INV-7
    on = HOSTSETUP.index("--cableconnected1 on")
    fin = HOSTSETUP.index("} finally {", on)
    assert HOSTSETUP.index("try {") < on                                 # the cable goes in inside the try
    tail = HOSTSETUP[fin:]
    assert "setlinkstate1 off" in tail and "--cableconnected1 off" in tail
    assert "emptydrive" in tail and "Remove-Item $iso" in tail            # discs out, the ISO (password) deleted


def test_one_pc_setup_locks_the_vm():                                   # INV-6, VM can't reach host services
    for setting in ("--nic1 nat", "--nat-localhostreachable1 off", "--clipboard-mode disabled",
                    "--drag-and-drop disabled", "--usb-xhci off", "--audio-enabled off", "sharedfolder remove"):
        assert setting in HOSTSETUP, setting


def test_one_pc_setup_password_handling():
    assert "RandomNumberGenerator" in HOSTSETUP                         # generated, not typed or reused
    assert "--passwordfile $pwFile" in HOSTSETUP and "--password " not in HOSTSETUP
    assert '/inheritance:r /grant:r "$($env:USERNAME):F"' in HOSTSETUP   # guest.pw: host user only
    assert "-AsSecureString" in HOSTSETUP                                # the API key is not echoed


def test_provision_from_disc():
    assert "[switch]$FromDisc" in PROV and "fatbox-setup.json" in PROV
    assert 'Assert-Signed $exe "Oracle"' in PROV and "/S" in PROV        # Guest Additions, signer checked
    assert "New-LocalUser" in PROV and "S-1-5-32-544" in PROV             # own admin user, client's untouched
    assert "-SubmitSamplesConsent 2" in PROV and "SpynetReporting" in PROV   # never send files to Microsoft
    assert "powercfg" in PROV and "setup-done.txt" in PROV
    assert "GIT_TERMINAL_PROMPT" in PROV                                 # private repo: no sign-in pop-up


def test_no_drive_qualified_variables_in_scripts():
    """0.40.1: "$want:" broke setup-host.ps1 on Windows PowerShell 5.1 (read as a drive like $env:). Write ${want}:."""
    import re
    scopes = r"(?:env|script|global|using|local|private|function|variable|alias)"
    bad = re.compile(r"\$(?!" + scopes + r":)[A-Za-z_][A-Za-z0-9_]*:(?!:)")
    root = Path(__file__).resolve().parents[1] / "scripts"
    found = []
    for f in sorted(root.rglob("*.ps1")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
            if bad.search(code):
                found.append(f"{f.name}:{n}: {line.strip()}")
    assert not found, found


def test_setup_discs_reuse_the_vms_sata_controller():
    """0.40.2 live test: a VM made in VirtualBox already has a SATA controller, and a second one is refused."""
    assert 'storagecontrollertype$i=`"IntelAhci`"' in HOSTSETUP      # finds the VM's own SATA controller
    assert "$ownCtl = $false" in HOSTSETUP and "--medium none" in HOSTSETUP   # takes out only its own drives
    assert "if ($ownCtl -and $state -ne \"running\")" in HOSTSETUP    # never removes the VM's own controller
    assert "--port $discPorts[0]" in HOSTSETUP and "--port 0 --device 0 --type dvddrive --medium $iso" not in HOSTSETUP


def test_vm_picker_takes_number_or_name_and_failure_is_not_reported_as_done():
    assert "[Console]::ReadKey($true)" in HOSTSETUP and '"UpArrow"' in HOSTSETUP     # arrow-key picker
    assert "[Console]::IsInputRedirected" in HOSTSETUP and "if ($list -contains $n)" in HOSTSETUP   # typed fallback
    assert "elseif ($ok) { Say \"network unplugged, setup discs removed\" }" in HOSTSETUP
    assert "if (Test-Path $pwFile) {" in HOSTSETUP and "$pwFile.bak-" in HOSTSETUP   # old password kept


def test_guest_additions_disc_by_path():
    """0.40.3 live test: VBoxManage 7.2 refused "--medium additions" ("Could not find file ...\\additions")."""
    assert "--medium additions" not in HOSTSETUP and "--medium $gaIso" in HOSTSETUP
    assert "Default Guest Additions ISO" in HOSTSETUP and "VBoxGuestAdditions.iso" in HOSTSETUP


def test_beta_never_asks_for_a_github_token():                         # fatbox-beta is public: no token, ever
    import re
    for name, text in (("provision-vm.ps1", PROV), ("new-test-vm.ps1", NEW), ("setup-host.ps1", HOSTSETUP)):
        for line in text.splitlines():
            if "Read-Host" in line:
                assert not re.search(r"token|github|pat\b", line, re.I), f"{name} asks for a token: {line.strip()}"
    assert "fatbox-beta" in PROV and "fatbox-beta" in NEW
    assert "ghToken" not in HOSTSETUP and "token =" not in HOSTSETUP    # no token on the setup disc either
    assert "$setup.token" not in PROV


def test_no_token_the_vm_gets_the_hosts_code():
    """0.42.0: the VM never logs in to GitHub. setup-host.ps1 puts this PC's code on the setup disc as a git bundle,
    new-test-vm.ps1 copies one in, and provision-vm.ps1 clones from it and never fetches."""
    assert "token" not in HOSTSETUP.split("# 5. The setup disc", 1)[1].lower().replace("no token", "")
    assert 'bundle create --quiet (Join-Path $stage "fatbox.bundle") HEAD' in HOSTSETUP
    assert "-Bundle C:\\fatbox-setup\\fatbox.bundle" in NEW and "bundle create --quiet $tmp HEAD" in NEW
    assert '$b = Join-Path $PSScriptRoot "fatbox.bundle"' in PROV and "& $git clone --quiet $Bundle $Dest" in PROV
    assert "if ($Bundle) { & $pyExe -m fatbox update --no-fetch }" in PROV
    assert "$setup.token" not in PROV
