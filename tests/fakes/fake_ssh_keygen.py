"""Stand-in for ssh-keygen in tests: makes a fake key pair, or prints a fingerprint for a known_hosts file."""
import sys

argv = sys.argv[1:]
f = argv[argv.index("-f") + 1]
if "-l" in argv:
    line = open(f).read().split()
    print(f"256 SHA256:fp-{line[-1][-6:]} 10.99.0.2 (ED25519)")
else:
    open(f, "w").write("PRIVATE\n")
    open(f + ".pub", "w").write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestsOnly000000000000000000 fatbox-host\n")
