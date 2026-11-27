# FatBox in the analysis VM

Install, update and command-line use of the VM side. The host GUI is in [HOST.md](HOST.md).

## Install

**Easiest (one PC):** run `scripts\setup-host.ps1` on the host ([HOST.md](HOST.md), "One PC: quick setup").
In the VM you only double-click **Setup.cmd** on the FatBox disc; nothing else by hand.

**Or by hand, one command:** in a fresh Windows 10/11 VM with VirtualBox Guest Additions, a local account with a password, and the
network on: open **PowerShell as administrator** and paste this one line:

```powershell
irm https://raw.githubusercontent.com/Knight007-hash/fatbox-beta/main/scripts/lab/provision-vm.ps1 -OutFile $env:TEMP\p.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\p.ps1
```

It does everything: Windows Update and SmartScreen off, a Defender exclusion for FatBox, the VC++ runtime,
Python 3.13 and Git (each installer's signature checked), FatBox cloned to `C:\fatbox` with its pinned
libraries, and it asks once for your free MalwareBazaar API key (https://auth.abuse.ch/). No GitHub account
or token is needed. At the end it prints the values for the host's `host.toml`.

Then shut the VM down, run `scripts\lab\lock-vm.ps1 -Vm "<VM name>"` on the PC that runs VirtualBox
(network off, clipboard, drag-and-drop and shared folders off), start the VM, and in the FatBox GUI:
Snapshots → **Make clean snapshot**.

## Update (every time new code is pushed)

```powershell
cd C:\fatbox; python -m fatbox update
```
Fast-forward only. It never touches `config.toml` or `data\`, refuses to overwrite local edits, and prints
the new version. Every update also checks the libraries against the pinned list (see below) and installs
only what differs; when everything matches it downloads nothing. A failed library install is retried by
just running the update again.

### Libraries (pinned)

`requirements.txt` is generated, never edited by hand. It pins every library, including the ones pulled
in indirectly, to one exact version with sha256 hashes, and allows only ready-made files (no building from
source). pip refuses any file whose hash differs. To upgrade (a dev machine, not the VM):

```powershell
python -m pip install pip-tools==7.6.2
# edit requirements.in only if you add or remove a library
python scripts/pin_deps.py        # newest versions that are at least 7 days old, with hashes
python scripts/check_deps.py --online
```
The capa rules and library signatures are not Python libraries: they are pinned files in `rules/capa/` and are
upgraded by hand with the `flare-capa` version (see `rules/capa/README.md`).

Open a PR. CI (`deps.yml`) checks the hashes, that every file exists for Windows + Python 3.13 and that
its native modules are built for 3.13 (`check_deps.py --wheels`), the 7-day wait and known vulnerabilities (pip-audit); it also runs weekly on `main`. After merge: Update VM.

## Command line (PowerShell)

```powershell
cd fatbox
py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install --require-hashes --only-binary :all: -r requirements.txt
copy config.example.toml config.toml
$env:MB_API_KEY = "<your abuse.ch Auth-Key>"   # free: https://auth.abuse.ch/
python -m fatbox sources                        # verify keys, downloads nothing

python -m fatbox fetch --max 5                  # last 60 min of MalwareBazaar, filtered by config
python -m fatbox triage                         # static triage of everything pending
python -m fatbox list
```

**GUI:** runs on the host, not in the VM (browse, pick, fetch, reports): see [HOST.md](HOST.md).

Other fetch modes:
```powershell
python -m fatbox fetch --mode signature --value AgentTesla --max 10
python -m fatbox fetch --mode tag --value ransomware --max 10
python -m fatbox run                            # fetch + triage in one go
python -m fatbox import .\sample.zip --password infected   # manual import
python -m fatbox baseline                       # score 50 clean System32 files: which rules fire on clean files?
python -m fatbox baseline --max 200 --no-capa   # more files, faster (no code analysis)
python -m fatbox capa-compare --max 10         # capa twice per sample: full vs library emulation skipped; any lost finding?
```

Output per sample: `data/reports/<sha256>/static.json` and `static.md`.

## Schedule it

```powershell
schtasks /create /tn fatbox-hourly /sc hourly /tr "C:\path\fatbox\.venv\Scripts\python.exe -m fatbox -c C:\path\fatbox\config.toml run"
```
(Set `MB_API_KEY` as a user environment variable so the task sees it, and use absolute paths in `config.toml`.)

## YARA

Drop more rule files into `rules/yara/` (subfolders fine). Good free sets: YARA-Forge (core),
Neo23x0 signature-base, ReversingLabs yara-rules. Broken files are skipped with a warning.

## Tests (dev machine)

```powershell
pip install --require-hashes -r requirements.txt; pip install pytest; python -m pytest -q
```
Offline: synthetic bytes + a benign PE (pip's launcher stub); no network, no live malware.
GitHub Actions runs the same suite on every pull request (`.github/workflows/tests.yml`).
