# Security

## Reporting a vulnerability
Please report security problems privately via GitHub's **Report a vulnerability** button
(Security tab → Advisories) instead of opening a public issue. Include steps to reproduce,
the affected version (`python -m fatbox --version`), and the impact. Expect a first reply within 7 days.

In scope: anything that could let a sample or hostile metadata escape containment, such as
plaintext samples written to disk, path traversal, XSS in the GUI from source metadata,
parser crashes that stop triage, the GUI being reachable beyond 127.0.0.1, or credential leaks.

## Safe-use requirements
- Run FatBox **inside an isolated analysis VM**, never on a daily-use machine.
- Never extract `*.zip.quarantine` files on a host OS. FatBox only decrypts in memory for static analysis.
- Keep API keys in environment variables, not in `config.toml`, and never commit `config.toml`.
- The GUI binds to `127.0.0.1` only. Don't expose it with port forwarding or a reverse proxy.
- Do not upload samples, `data/` or reports to this repository or to issues.
