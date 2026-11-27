# FatBox

> **Beta (0.43.0).** Temporary public copy for university review.

FatBox is an automated malware analysis lab that fits the machines you have: one PC or two, with the
controller on a real PC or inside a VM. It downloads real malware samples into an isolated analysis machine,
studies them without ever running them, and shows the results in a simple app on your PC.

> **For defensive research and education only.** FatBox handles live malware. Use it only with an isolated
> analysis machine, and never share the samples.

## How it works

```
  YOUR PC                                 ANALYSIS VM  (isolated, network off)
 ┌────────────────────────┐              ┌─────────────────────────────┐
 │ FatBox app             │──── asks ───>│ 1 Download   sha256 checked │ <── internet, only
 │ · never holds a sample │              │ 2 Lock       password zip   │     while fetching
 │ · checks every reply   │<── reports ──│ 3 Analyse    never runs it  │
 │ · keeps your reports   │   JSON only  │                             │
 └────────────────────────┘              └─────────────────────────────┘
```

1. **Pick** samples from MalwareBazaar in the FatBox app on your PC.
2. **Fetch:** the VM goes online only long enough to download them, checks each sha256 and locks every
   file in a password zip. It is never stored as a plain file.
3. **Analyse:** the VM reads each file in memory and never runs it: file type, packer, imports, strings,
   code capabilities (capa), YARA, and a 0-100 risk score with the reasons.
4. **Read:** only the JSON report crosses back. Your PC checks it before showing it and keeps it in your library.
5. **Reset:** Revert puts the VM back to its clean snapshot. Your reports stay on your PC.

**Updates:** Update VM copies your PC's own FatBox code into the VM, so the VM never signs in to anything.

## Safety first

- Samples never leave the analysis machine; only text reports come back.
- Samples are stored locked and are never run.
- The app treats everything from the analysis machine as untrusted.
- The analysis machine is online only while it downloads, and is cut off right after.

## Planned

1. **Dynamic analysis:** run a sample in a throwaway machine with fake internet and record what it does.
2. **More lab setups:** a Linux or Windows host with one or many isolated analysis machines.
3. **Upload your own file** to analyse.

## Limitations

- Static analysis only for now. VirtualBox and a Windows host only for now.
- The risk score is a heuristic and can flag some clean programs.

## Setup

**One PC, one script:** you need VirtualBox 7 and a fresh Windows VM (just Windows installed, powered off).
On your PC: clone this repo and run `powershell -ExecutionPolicy Bypass -File .\scripts\setup-host.ps1`, pick the
VM. In the VM: open the FATBOX disc, double-click **Setup.cmd**, click Yes. Nothing else by hand in the VM.
Steps: [HOST.md](HOST.md), "One PC: quick setup".

**Or the analysis VM by hand, one command** (Guest Additions installed, PowerShell as administrator, network on):

```powershell
irm https://raw.githubusercontent.com/Knight007-hash/fatbox-beta/main/scripts/lab/provision-vm.ps1 -OutFile $env:TEMP\p.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\p.ps1
```

It installs everything FatBox needs inside the VM. Details: [VM.md](VM.md). The app on your PC: [HOST.md](HOST.md).

**Tests** (offline, no real malware): `pip install --require-hashes -r requirements.txt`, `pip install pytest`,
`python -m pytest -q`.

## AI assistance

Designed and directed by the author, built with heavy help from an AI coding assistant (Claude, by
Anthropic). Much of the code, tests and docs were written by the assistant under the author's review; every
change was reviewed and merged by the author.

## License

MIT ([LICENSE](LICENSE)). Third-party rules in `rules/capa/` are Apache-2.0 (Mandiant).
