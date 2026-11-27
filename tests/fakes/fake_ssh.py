"""Stand-in for ssh.exe in tests: plays the test PC. Pins/checks the host key like OpenSSH, then runs the real
gate (scripts/lab/fatbox_gate.py, copied next to its fatbox_gate.toml in FAKE_GATE_DIR) as sshd's forced command."""
import os
import subprocess
import sys

argv = sys.argv[1:]
opts = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-o"]
kh = next(o.split("=", 1)[1] for o in opts if o.startswith("UserKnownHostsFile="))
strict = next(o.split("=", 1)[1] for o in opts if o.startswith("StrictHostKeyChecking="))
host_key = os.environ.get("FAKE_HOST_KEY", "ssh-ed25519 AAAAtestpc")
if os.environ.get("FAKE_SSH_DOWN"):
    sys.exit("ssh: connect to host 10.99.0.2 port 22: Connection timed out")
pinned = open(kh).read().strip() if os.path.exists(kh) else ""
if not pinned:
    if strict != "accept-new":
        sys.exit("Host key verification failed.")
    with open(kh, "w") as fh:
        fh.write(f"10.99.0.2 {host_key}\n")
elif host_key not in pinned:
    print("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", file=sys.stderr)
    print("Host key verification failed.", file=sys.stderr)
    sys.exit(255)
cut = argv.index("--")
command = " ".join(argv[cut + 2:])          # what sshd sees as SSH_ORIGINAL_COMMAND
gate_dir = os.environ["FAKE_GATE_DIR"]
env = {**os.environ, "SSH_ORIGINAL_COMMAND": command, "SSH_CLIENT": "10.99.0.1 50000 22"}
sys.exit(subprocess.call([sys.executable, "-I", os.path.join(gate_dir, "fatbox_gate.py")], env=env))
