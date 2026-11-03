#!/usr/bin/env python3
"""Confinement probe for the P3 test runner. Runs INSIDE the sandbox as the candidate would. Exits 0 only if the sandbox holds; prints the names of failed checks otherwise.
A negative control: run unsandboxed it must fail. Python 3.9+ stdlib only, no network use except the attempts that MUST fail."""
import glob, os, socket, subprocess, sys
bad = []
if os.getuid() != 65534: bad.append("not-nobody")
try: socket.create_connection(("1.1.1.1", 443), timeout=4).close(); bad.append("network-reachable")
except OSError: pass
try: socket.gethostbyname("api.github.com"); bad.append("dns-reachable")
except OSError: pass
for k in os.environ:
    if k.startswith(("GITHUB_", "ACTIONS_", "RUNNER_", "INPUT_")) or "TOKEN" in k or "SECRET" in k: bad.append("env-leak:" + k)
for p in glob.glob("/proc/[0-9]*/environ"):
    try: data = open(p, "rb").read()
    except OSError: continue
    if p.split("/")[2] != str(os.getpid()) and (b"ACTIONS_RUNTIME_TOKEN" in data or b"GITHUB_TOKEN" in data): bad.append("other-process-environment-readable"); break
for d in ("/home/runner/work", "/home/runner", "/etc", "/usr/local/bin"):
    if os.path.isdir(d):
        try: open(os.path.join(d, ".probe-%d" % os.getpid()), "w").close(); os.remove(os.path.join(d, ".probe-%d" % os.getpid())); bad.append("writable:" + d)
        except OSError: pass
if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0: bad.append("sudo-works")
print("PROBE_PASS" if not bad else "PROBE_FAIL " + ",".join(sorted(set(bad))))
sys.exit(0 if not bad else 1)
