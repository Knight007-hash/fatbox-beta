# Host controller

Control fetching in the VM from a GUI on the host, and read the static reports on the host.

```
HOST (Windows 11)                                   analysis VM (Windows 11)
python -m fatbox.host gui  (127.0.0.1:8790)
   |  VBoxManage guestcontrol run  ------------>   python -m fatbox fetch/triage/list/report
   |  <---- stdout: JSON only (list, report)        samples stay here as *.zip.quarantine
```

- Transport is VirtualBox's own guest control (Guest Additions). No agent, no listener, no shared folder.
- Only JSON crosses back: the sample list and `static.json` reports. Never a sample.
- The host treats all VM output as hostile: size caps (list 2 MB, report 4 MB, process killed past the cap),
  schema checks, sha256 must match the one requested, re-serialized before caching, rendered with
  `textContent` only, strict CSP. Fetch options are an allow-list (no free text reaches the guest).
- The guest password lives in a file in `%APPDATA%\fatbox-host\` (outside the repo) and is passed with
  `--passwordfile`, never on a command line.
- Host side is standard library only (Python 3.11+). It does not need pyzipper/pefile/yara.
- The host GUI needs a per-run token (in the URL printed at start, then an HttpOnly cookie). VirtualBox NAT
  can expose the host's 127.0.0.1 to the guest as 10.0.2.2, so the token is what keeps the VM out of it.

## One PC: quick setup

You need VirtualBox 7 and a fresh Windows 10/11 VM in it (just Windows installed), powered off.

1. **Host:** `git clone https://github.com/Knight007-hash/fatbox-beta.git C:\fatbox-host`, then in PowerShell:
   `cd C:\fatbox-host` and `powershell -ExecutionPolicy Bypass -File .\scripts\setup-host.ps1`.
   Pick the VM from the list and paste your free MalwareBazaar key (or Enter for later). The script sets up the
   host, writes host.toml, locks the VM's settings and starts the VM with a "FatBox setup" disc in it.
2. **VM:** sign in, open **This PC → FATBOX disc → Setup.cmd**, click **Yes**. It installs the Guest Additions,
   Python, Git and FatBox and switches off what gets in the way (15-40 minutes, maybe one restart). FatBox's code comes
   from this PC on the disc (0.42.0).
3. **Host:** the script notices when FatBox answers in the VM, unplugs the network, removes the discs and makes
   the desktop shortcut. Open **FatBox Host → Snapshots → Make clean snapshot**. Done.

FatBox logs in to the VM as its own local user `fatbox` (hidden from the sign-in screen) with a generated
password kept in `%APPDATA%\fatbox-host\guest.pw`; your own VM account is not changed. Tamper Protection can't
be switched off by a script (Windows blocks it); FatBox works with it on. The steps below are the manual way.

## Setup (once)

1. **VM**: pull the new code: `python -m fatbox update`. Then run `where python` and note the full path
   (not the `WindowsApps` one).
2. **VM**: put the MalwareBazaar key in a *user* environment variable (`setx MB_API_KEY ...`), not in
   `config.toml` (see SECURITY.md). Processes started by guest control don't see variables set only in one console.
3. **Host**: install Python 3.11+ and clone the repo anywhere, e.g.
   `git clone https://github.com/Knight007-hash/fatbox-beta.git C:\fatbox-host`, then `cd C:\fatbox-host`.
4. **Host**: `python -m fatbox.host init`, then edit `%APPDATA%\fatbox-host\host.toml`
   (set `guest_python` to the path from step 1; check `vm` matches the VM name exactly).
5. **Host**: create the password file and lock it to your user:
   ```
   notepad %APPDATA%\fatbox-host\guest.pw          (one line: the guest account's password, save)
   icacls %APPDATA%\fatbox-host\guest.pw /inheritance:r /grant:r "%USERNAME%:R"
   ```
   The guest account must have a password; guest control refuses empty ones.
6. **Host** (VM running): `python -m fatbox.host check` -> expect `VM '<your VM name>': running` and
   `guest: FatBox <the same version as the host>`.
7. **Host**: `python -m fatbox.host gui` (opens the tokenized URL; if the browser didn't open, copy it from the console).
   **Desktop shortcut, no console window:** `cd C:\fatbox-host` then `.venv\Scripts\python -m fatbox.host shortcut`
   (use the same Python you run FatBox with). It makes (or replaces) "FatBox Host" on the desktop, which starts
   `pythonw.exe -m fatbox.host gui`. Stop it with **Quit** in the page. A second double-click opens the running GUI
   instead of starting another one. Errors show in a message box; everything else goes to `host.log` (1 MB,
   one old copy kept) next to `host.toml`, together with the GUI's URL.
   0.27.0: the shortcut and the browser tab show the FatBox rune icon (`fatbox/host/assets/fatbox.ico`).
   0.43.0: the GUI uses drawings from Theodor Kittelsen's *Svartedauden* (1900, public domain): a softly blurred backdrop on the Lab tab (0.43.1), a
   wait screen while Windows boots (Hide closes it), art in empty lists, and a faint forest background that
   Settings → Appearance turns off. Credits: `fatbox/host/assets/art/CREDITS.txt`.
   After updating from an older version, run `python -m fatbox.host shortcut` once more to get the new icon.
8. **Host, VM powered off** (hardening, once; VirtualBox 7.x syntax):
   ```
   VBoxManage modifyvm "<VM name>" --nat-localhostreachable1 off
   VBoxManage modifyvm "<VM name>" --clipboard-mode disabled --drag-and-drop disabled
   ```
   The first stops the VM reaching host loopback services at all. Use a guest password you use nowhere else.

Then take a snapshot of the VM ("clean + host control").

## Fresh test VM (T-19, 0.36.0)

You don't need an existing VM. FatBox builds one from a Windows ISO; Microsoft's free
Windows 11 Enterprise Evaluation ISO works.

1. On the PC whose VirtualBox will hold the test VM (this PC, or the test PC in a two-machine lab), open a
   FatBox folder (git clone) and go to `scripts\lab`: the script packs that folder's code for the VM.
2. In a normal PowerShell there:
   `powershell -ExecutionPolicy Bypass -File .\new-test-vm.ps1 -Iso D:\path\Win11.iso`
   It asks for a new password for the VM's user (`analyst`), then needs no clicks for
   30-90 minutes: VM with safe settings (cable out, no clipboard, drag-and-drop, shared folders, USB or
   audio), unattended Windows install, then Python, Git, the VC++ runtime and FatBox inside, with the network
   plugged in only for that last part. Defaults fit a mid-range PC: 4 CPUs, 8 GB RAM, 80 GB disk
   (`-Cpus`, `-MemoryMB`, `-DiskGB` to change).
3. It prints the values for `host.toml` (one PC) or for `lab-setup.ps1` (two machines). Put them in.
4. FatBox GUI → Snapshots → **Make clean snapshot**. Done.

**Already have a fresh Windows VM?** ("Prepare existing VM") Install VirtualBox Guest Additions in it and
make a local account with a password. With the VM's network on, run the one-line installer from
[VM.md](VM.md) in PowerShell "Run as administrator" (no token needed). Shut the VM down, run
`scripts\lab\lock-vm.ps1 -Vm "<its name>"` on the PC that runs VirtualBox, start the VM, then
**Make clean snapshot**.

If Defender's real-time protection stays on (Tamper Protection), the script says so; FatBox still works
thanks to the folder exclusion, or switch it off by hand in Windows Security.

## Two machines (T-19, 0.35.0)

FatBox works the same when the test VM runs on another computer: a second PC, or the real PC under two VMs
(GUI in one VM, test VM in another). The test machine must run the test VM in VirtualBox; a test PC
without a VM is not supported (no clean snapshot to go back to).

```
  This PC (GUI, reports only)  ── SSH, key, cable ──▶  Test PC: VirtualBox ─▶ test VM (samples stay here)
```

1. **Link.** Connect the two PCs with a cable (or a switch used only for this) and give them fixed IPs, e.g.
   this PC 10.99.0.1 and the test PC 10.99.0.2. Give the test PC its own internet line, not your home LAN.
2. **Key, on this PC:** `python -m fatbox.host lab pair`. It makes the key and prints one command.
3. **Test PC:** install VirtualBox and Python 3.11+, and build the test VM there ("Fresh test VM" above). Copy
   `scripts\lab\lab-setup.ps1` and `scripts\lab\fatbox_gate.py` there (USB stick), open PowerShell with
   "Run as administrator" as the user who owns the VM, `cd` to them and run the command from step 2 (put this
   PC's IP in `-HostAddress`). It asks for the VM's guest password, which stays on the test PC, and prints the
   test PC's SSH fingerprint.
4. **Lab layout, on this PC:** Settings (gear) → Lab layout → pick the picture, type the test PC's address and
   login, **Save layout**, then **Test connection** (0.37.0; it shows the lab-setup command too). Or, by hand,
   add to host.toml
   ```
   [lab]
   layout = "two-pcs"      # or "two-vms"
   address = "10.99.0.2"
   login = "<the test PC user from step 3>"
   ```
   `password_file` is not needed any more.
5. **Check:** `python -m fatbox.host lab check`. The first run pins the test PC's key: compare the fingerprint
   with step 3. Then start the GUI as usual. Keep the test PC signed in with VirtualBox open.

## Daily use

| Host command | Does |
|---|---|
| `python -m fatbox.host gui` | browser UI with tabs: Fetch (limits, live log), Triage & Static Analysis (the report library, click a row for its report), Dynamic Analysis (later) |
| `python -m fatbox.host fetch --mode signature --value AgentTesla --max 3 --budget 400 --small-first` | same from the terminal (`--max-size-mb N` or `--no-size-limit`) |
| `python -m fatbox.host shortcut` | (re)make the "FatBox Host" desktop shortcut: GUI with no console window |
| `python -m fatbox.host update-vm` | update FatBox in the VM (same as the Update VM button) |
| `python -m fatbox.host list` | samples in the VM |
| `python -m fatbox.host report <sha256>` | validated report (from the library in `%APPDATA%\fatbox-host\library\`, else from the VM) |

## Settings (gear tab, right end of the tab row)

Since 0.23.0 the **Settings** tab holds what used to live only in config files, saved on this PC in
`settings.json` next to the library (never in the VM):

- **Fetch defaults**: download limit, time budget, and **auto-revert after triage** (saved at once). The
  Fetch tab folds what Browse and the next fetch will use into one **Fetch rules** button (0.33.0): mouse over it
  for the full list, click it to open Settings. (0.29.0: the
  samples count and smallest first left the GUI; they only matter to the command line `fetch`.) 0.25.0: **Update VM** moved here too (card "FatBox in the VM"); the red
  version bar still offers it when host and VM differ.
- **Filters**: file types (Office covers doc, xls, ppt and msi), only-these tags, never-these families,
  smallest file. 0.29.0: Browse applies them, plus the download and unpack limits: rows they would skip are
  not listed ("N hidden by Settings"). The Fetch tab's Show menus only narrow that list further.
- **Analysis**: time per sample, extra time for capa, samples at once (Auto = one per VM CPU, as far as free RAM allows), capa on
  packed programs (skip, or run anyway). These replace `sample_time_s` / `capa_time_s` in host.toml once you
  save Settings; until then host.toml's values are the defaults.
- **Files over the unpack limit** (🔒): the zip-bomb guard can be 25, 50 or 100 MB, never higher or off.
  A bigger sample is skipped, or with "keep its info only" shows in the library as **too big · not analysed**
  (family, type, tags; the file itself is never kept).
- **API keys** are not here: they stay in the VM and are never shown or typed in the browser.

Every value is checked by the host when you save and again by the VM with each fetch.

The **Triage & Static Analysis** tab has two views: **New** (every report waiting for you to Save or Discard
it; 0.28.0: a row leaves New as soon as you do) and **Library** (the reports you saved, with search and Delete).
0.26.0: in **New**, tick reports (or **Select all**) and click **Save to library** to keep them, or **Discard**
to drop them. Until you choose, a report waits as **not saved**: it is already copied to this PC, so a revert
or auto-revert never loses it. A discarded report is deleted from this PC and is not copied again while its
sample is still in the VM. Reports saved before 0.26.0 count as saved.

## VM control (GUI top bar)

Since 0.22.0 the header holds everything about the VM on one line: name and state, Start (and the window icon for
Start with window), Shut down, Power off, the **Network** chip (green "Network off"; click it to connect or
disconnect by hand), Revert (0.25.0: always to the ★ default; any other snapshot from the Snapshots tab) and Snapshot, then the sun/moon button (white or dark
mode, remembered in this browser) and Quit. The activity log is a panel on the right; its corner button hides
it and "Activity log" at the end of the tab row brings it back.

All of this is host-side `VBoxManage`; nothing new runs in the guest.

| Button | VBoxManage | Notes |
|---|---|---|
| Start (headless / window) | `discardstate` if the VM holds saved memory, `modifyvm --cableconnected1 off`, `startvm --type headless\|gui`, then the cable is checked and unplugged again if needed | only when the VM is off. The VM never boots online, even when a snapshot has the cable in |
| Shut down | `controlvm acpipowerbutton` | clean; Windows can take a minute or ignore it |
| Power off | `controlvm poweroff` | asks first; the fallback when Shut down doesn't work. 0.39.3: also works on a hung VM (stuck, paused, stopping, starting) |
| Network Connect / Disconnect | `controlvm setlinkstate1` (running) or `modifyvm --cableconnected1` (off) | virtual cable on NIC 1; NAT config is kept. Disconnected = no network at all. Not needed for Fetch or Update VM; Connect warns first and stays on until you Disconnect |
| Update VM | 0.42.0: copies this PC's FatBox code into the VM (cable out), then cable in for `fatbox update --no-fetch` (pinned libraries), cable out | nothing to set up in the VM, no token; the VM ends on the host's exact version. Remote lab: the VM's own `fatbox update` from GitHub |
| Revert | `controlvm poweroff` + `snapshot restore` + `discardstate` (VM left off; Start boots it fresh) | asks first; the header button always uses the ★ default snapshot, each row in the Snapshots tab has its own Revert (Snapshots tab; `clean_snapshot` in `host.toml` until you pick one). A running VM's reports are copied to the library first |
| Take snapshot | `snapshot take` | only while the VM is off (0.39.3: a running VM's RAM, which can hold sample bytes, would be saved on the host); names: letters, digits, `. _ -` |

Buttons only work at the right time, and the host enforces the same rules (not just the page):
one VM action at a time (everything is locked until it finishes); Start only when off; Shut down / Power off
only when running; nothing while the VM is mid-change (starting, stopping, restoring); Fetch and Update VM
only when the VM is running and no VM action is in progress. Power off, Shut down, Revert, Connect and
Disconnect are refused while a fetch or update is running (cancel it first).

**Versions.** Host and VM must run the same FatBox version. If they differ, a red line appears under the header
and Fetch is off: click **Update VM** (or, if the VM is newer, run `git pull` on the host). `python -m fatbox.host
check` prints the same comparison.

**Network (INV-7).** Fetch and Update VM plug the VM's cable in themselves and unplug it afterwards, however
they end. Analysis (triage) runs only after the cable is out. If the cable can't be unplugged after 3 tries,
analysis is blocked and the log says NETWORK STILL ON: click Disconnect, or power off the VM. When the host
GUI starts and finds the cable plugged in (a crash, or Connect by hand), it unplugs it and says so in the log.
Start and Revert unplug it too, because a snapshot can bring the cable back. The badge next to Network shows
OFF, ON (job running), or ON (manual) in red.

**Browse, fetch, triage (0.29.0).** The Fetch tab is three steps. Since 0.33.0 the Fetch tab's own
label says which one (Fetch · Browse & pick, Fetch · Fetching 2 of 3, Fetch · Triage · 3 ready), so you see it
from any tab; the value box next to Mode shows only for tag, family and file type:

1. **Browse & pick.** Choose Mode (and value), **List** 25, 50 or 100 rows (newest first), click **Browse**: the
   VM asks MalwareBazaar (the cable is in for a few seconds; metadata only, no files). Rows your Settings filters
   would skip are left out. The table shows a pre-score (from the metadata, made by the host), family, category,
   type, size and tags. **Show** menus narrow it: Category (ransomware, wiper, rat, stealer, banker, backdoor,
   loader, worm, miner, unlabeled), Family and Tags (built from the list, with counts and a search box),
   Pre-score, First seen, Hide (already in the VM / in the library). Click a header to sort. Nothing is ticked
   for you: tick up to 30 rows.
2. **Fetch selected** downloads exactly those (network ON, then OFF, with the download limit, time budget and
   unpack limit). Nothing is analysed yet. The tab then lists what arrived and what didn't.
3. **Triage N in VM** runs the static analysis offline (the host unplugs the cable first if someone plugged it
   in by hand), copies the reports to the library and opens Triage & Static → New. Auto-revert, if on, runs
   after this step as its own job (0.38.0): the reports show at once while the VM resets, and Fetch waits
   for it. The Activity log prints how long each step took. Samples fetched but not triaged (say, after closing the page) bring step 3 back next time.

**Reading a report (0.30.0).** A report opens with the answer first: a score ring (score and priority), the
family and its category, one plain sentence built by fixed rules from the report's own findings (no AI, no
guessing; a low score always adds "not proof that the file is safe"), then type, size, signature, compile date and
the SHA-256 with **Copy**. **Key findings** lists up to 5 findings in plain words (from capa topics, File Analysis,
string indicators, YARA and IOCs), each with a severity bar and its ATT&CK ID in grey. **Why N points** is one bar
split by score rule. Everything else is folded, one click away: File, What the code does, Network indicators
(defanged like `hxxp://bad[.]top`, never links, with **Copy** and **Copy all**), Registry keys, paths and wallets,
Strings/imports/YARA, Hashes and PE details, Every score line (the +0 ones too) and Raw JSON.

**File Analysis.** Each report has a **File analysis** section (folded, under "Why N points"): type, compiler, packer,
protector, installer/SFX, runtime, overlay, signature (signer, valid or INVALID, or "validity not checked") and
a packed? verdict with its reason, plus the engine versions. The Triage table's **File** column is a short badge
the host writes from those checked fields, e.g. `PE32 · UPX 3.96 · packed`; ⚠ marks a protector or a broken
signature; `timeout` / `engine crashed` / `engine missing` mean the engine failed (the rest of the report is
complete); — means a report made before 0.17.0. `DIE: no signature matched` means the engine ran and recognised
nothing. Section names alone don't make a file packed: if they say UPX but DIE finds no UPX code and the entropy is
low, Packed? says `no` and why (renamed sections are a common trick).

**Network IOCs in the score (0.17.2).** URLs and IPs that nearly every normal program carries give no points: XML
schema links (w3.org, schemas.microsoft.com), certificate links (crl./ocsp., CA sites), URL templates
(`http://%s`), version numbers that look like IPs (`1.0.0.0`), OIDs and public DNS servers (`8.8.8.8`). They stay
in the report's IOC list. "Why this score" says how many were counted and how many ignored, e.g.
`+5 embedded network IOCs (2 counted, 11 ignored as noise)`. Reports made before 0.17.2 keep their old score.

**Malware family named by DIE (0.17.2).** DIE has stub signatures for some .NET RATs (NjRAT, XWorm, VenomRAT,
RevengeRAT) and old DOS viruses. A match gives `+25 DIE names a malware family: NjRAT 0.7D` and the File badge
shows `PE32 · NjRAT 0.7D · malware ⚠`. A heuristic guess from DIE gives no points.

**One fact, points once (0.17.2).** The YARA rule `FB_UPX_Packed` only sees the UPX section names, so when the
packer line already scored them it gives `+0 YARA FB_UPX_Packed: same fact as the packer line`. Other YARA rules
still give +20. A packed file can't show much more to static analysis: expect medium, not high, until unpacking
exists.
Each string behaviour counts once (vssadmin and wmic both deleting shadow copies is one behaviour). Shadow copy
deletion together with ransom note language adds `+15 ransomware pattern: backups wiped + ransom note`.

**What the code does (capa, 0.18.0).** Each report has a **What the code does** block after File analysis: the
capabilities capa found in the sample's code (topic, capability, ATT&CK technique) and whether each one counts.
The Triage table's **Code** column is a short badge, e.g. `14 capabilities · injection ⚠`; ⚠ marks injection,
impact, a malware family, anti-analysis or collection. `capa: timeout` / `capa crashed` / `capa missing` mean the
engine failed (the rest of the report is complete); `not a PE: skipped` means the file is not a Windows program;
— means a report made before 0.18.0. A packed file shows only its unpacking stub: `packed: code hidden`.
Points per topic, once each: injection +15, anti-analysis, persistence, collection, load-code +10, communication
+5, all of capa at most +40. Rows marked `0 pts` are shown but never scored: a file-wide string match, a draft
(nursery) rule, everyday code like reading a file, or (0.18.3) everyday PE reading: parse PE header, access PE
header, enumerate PE sections, inspect section memory permissions (packers, installers and runtimes do it too). A capability whose technique the strings already scored says
`+0 ... also seen in strings`. capa gets its own time limit, `capa_time_s = 120` in `host.toml` (30..600), on top of
`sample_time_s`; a big program can need a minute or two. The first analysis after an update is slower: capa
builds its rule cache once.

**Report library.** The Triage & Static Analysis tab shows the host's own library, not the VM, so it stays full
after a revert and works with the VM off. Reports are copied in after every fetch, when you click **Refresh**
(VM running), and before a **Revert**; if some can't be copied, Revert asks "revert anyway?". Only new or
changed reports are copied. **In VM** ✓ means the sample is still in the VM; — means it was reverted away
(the report stays). Click a row to open its report from the host's disk; click a header to sort. To delete,
tick saved rows that are no longer in the VM and click **Delete from library** (no undo); reports not saved
yet are dropped with **Discard** in New. Limits: 5,000 reports,
4 MB per report, 500 MB free disk; when one is hit, new reports aren't saved and the log says why. Nothing
is deleted automatically. Back it up by copying `%APPDATA%\fatbox-host\library\`. Reports you opened before
0.15.0 are added on the first start.

**Snapshots tab and the clean snapshot.** The Snapshots tab lists the VM's snapshots. ★ marks the default, which
Revert and auto-revert go back to; **Set default** changes it (remembered in `snapshots.json` next to the library,
so no host.toml edit). **Make clean snapshot** (VM running, same version): copies every report to the library,
deletes every sample and report in the VM (`wipe-data`), checks the VM lists 0 samples, restarts the VM, checks
again, shuts Windows down (the power button first; if Windows ignores it for 30 s, FatBox asks Windows itself to
shut down; if it is still on 30 s later, FatBox powers it off: the VM is idle, empty and offline then, 0.28.0), then takes `clean-fatbox-<version>-<date>` with the VM off and makes it the
default, marked **✓ checked by FatBox**; finally it starts the VM from it. If any step fails it stops and takes no
snapshot. Make a new one after each FatBox update: a yellow bar reminds you when
the default is older than the host, unchecked, or deleted. **Delete** asks first; the default can't be deleted.

**Auto-revert.** Tick **Auto-revert after triage** in Settings (off by default; remembered). After each triage
whose reports were all saved, the host reverts to the default snapshot and boots the VM fresh, headless (one
Windows start, a minute or two), then checks the cable is out and the version matches.

**Always a fresh boot (0.18.1).** FatBox never resumes a VM from saved memory: Start, Revert and auto-revert drop
it (`discardstate`) and boot Windows from the disk. When Windows keeps the CPU's virtualization for itself
(Memory integrity, Hyper-V, WSL2 or Docker; VirtualBox's log then says `VT-x is not available` and shows `NEM`
lines), VirtualBox runs on top of Hyper-V and resuming saved memory fails with "The VM session was closed before
any attempt to power it on". A clean snapshot made before 0.18.1 holds memory; it still works, booted fresh from
its disk, but make a new one. A cancelled triage, or a report that couldn't be
saved, means no revert; the log says why. Browse hides samples already in the library, so a revert doesn't make
you download the same sample twice.

**Analysis time limit.** Each sample gets 60 s of analysis (`sample_time_s` in host.toml, 10..300). A sample
that takes longer is stopped and shows status `timeout` in red; click it to read why. It is not retried
automatically. One analysis run takes at most 30 samples; the rest are done on the next fetch.

**Errors.** The GUI shows a short sentence (for example "Windows in the VM is not ready for FatBox yet... wait a minute");
VirtualBox's raw text is behind "details". A failed fetch says why in the activity log.

**Branches.** Update VM installs what is on GitHub `main`. If the host runs from another branch (testing a
PR), the GUI says so at start, and a version mismatch tells you to merge the PR first or `git checkout main`.

## Remaining risks (be honest about them)

- **Hypervisor escape.** Guest control rides on Guest Additions and the VirtualBox host-guest channel. A
  VirtualBox escape bug would bypass everything here. Keep VirtualBox updated; that risk exists for any VM.
- **Malware with admin in the VM** can tamper with the Guest Additions service or FatBox and send fake
  output. It can't make the host run anything: the host only parses capped JSON and shows text. Treat
  reports from a VM you suspect is compromised as untrusted, and revert to the clean snapshot.
- **Samples are never executed by FatBox**, but the VM still holds live samples. Don't detonate anything in
  this VM while it has NAT.

## Troubleshooting

- `The guest execution service is not ready (yet)`: wait until Windows in the VM has fully booted.
- `VERR_AUTHENTICATION_FAILURE` / logon failure: wrong password in `guest.pw`, or the account has none.
- `exit 1` on every command: wrong `guest_python` or `guest_dir` in `host.toml`.
- Fetch says no key: see setup step 2.
