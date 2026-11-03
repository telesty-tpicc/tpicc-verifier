#!/usr/bin/env python3
"""TPICC P3 independent test runner (DRAFT, unpublished). Python 3.9+ stdlib only. TRUSTED code, pinned by commit SHA in the test-runner workflow.
It is the only place candidate code is ever executed, and only as an unprivileged child process without network on a secretless, disposable runner.
  run      --records DIR --out DIR [--sandbox linux|none]   for every requests/<id>/ without results/<id>.json: check, extract, run the signed test command, write out/<id>.json
  publish  --out DIR --records DIR                          validate out/*.json against the request, then write records/results/<id>.json (the caller commits it)
The result file is written by this program, never by the candidate. The candidate's output is only ever a bounded, filtered text tail."""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, sys, tarfile, tempfile, time

ID_RE = re.compile(r"^[0-9a-f]{16}-[0-9]{1,3}$"); SHA_RE = re.compile(r"^[0-9a-f]{64}$"); ARG_RE = re.compile(r"^[A-Za-z0-9._/=-]{1,100}$")
MAX_TAR, MAX_FILES, MAX_BYTES, MAX_TAIL, MAX_PER_RUN = 50 * 2**20, 5000, 200 * 2**20, 1500, 5
RES_KEYS = {"schema", "id", "bundle_sha256", "argv_sha256", "exit_code", "timed_out", "duration_s", "output_tail", "run_id", "sandbox"}
REQ_KEYS = {"schema", "id", "bundle_sha256", "argv", "timeout_s", "requested_at"}

def sha256(b): return hashlib.sha256(b).hexdigest()
def argv_sha(argv): return sha256(json.dumps(argv, separators=(",", ":")).encode())
def jload(path):
    def nodup(pairs):
        d = {}
        for k, v in pairs:
            if k in d: raise ValueError("duplicate key")
            d[k] = v
        return d
    return json.load(open(path, encoding="utf-8"), object_pairs_hook=nodup)

def check_request(req, rid):
    if not isinstance(req, dict) or set(req) != REQ_KEYS or req["schema"] != "tpicc-test-request-v1" or req["id"] != rid: raise ValueError("malformed request")
    argv, t = req["argv"], req["timeout_s"]
    if not (isinstance(argv, list) and 2 <= len(argv) <= 6 and argv[0] in ("php", "python3") and all(isinstance(a, str) and ARG_RE.match(a) for a in argv)): raise ValueError("argv outside policy")
    if any(a.startswith("-") or ".." in a.split("/") or a.startswith("/") for a in argv[1:]): raise ValueError("argv outside policy")
    if not (isinstance(t, int) and 10 <= t <= 300) or not SHA_RE.match(str(req["bundle_sha256"])): raise ValueError("timeout or digest invalid")

def safe_extract(tgz, dest):
    """regular files and directories only; no absolute or dot-dot names; caps on count and size; modes reduced to 0644/0755"""
    n = total = 0
    with tarfile.open(tgz, "r:gz") as tf:
        for m in tf:
            name = m.name[2:] if m.name.startswith("./") else m.name
            if name in ("", "."): continue
            if not (m.isfile() or m.isdir()) or name.startswith("/") or ".." in name.split("/") or "\x00" in name: raise ValueError("unsafe archive member")
            n += 1; total += max(m.size, 0)
            if n > MAX_FILES or total > MAX_BYTES: raise ValueError("archive too large")
            target = os.path.join(dest, name)
            if m.isdir(): os.makedirs(target, exist_ok=True); continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tf.extractfile(m) as src, open(target, "wb") as out: shutil.copyfileobj(src, out)
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)

def unescape_mp(s): return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)

def confine_plan(mountinfo, rw):
    """mount points to remount read-only: every mount in this namespace except the two writable candidate mounts; the root mount must be among them"""
    mps = []
    for line in mountinfo.splitlines():
        f = line.split(" ")
        if len(f) > 5: mps.append(unescape_mp(f[4]))
    return [m for m in dict.fromkeys(mps) if m not in rw]

def cmd_confine(a):
    """runs as root inside `unshare --net --mount`: bind the candidate's tree and home as the only writable mounts, remount every other mount read-only, self-check, then exec the unprivileged command (fails closed)"""
    rw = [os.path.realpath(a.tree), os.path.realpath(a.home)]
    def mnt(*args): return subprocess.run(["/usr/bin/mount" if os.path.exists("/usr/bin/mount") else "mount"] + list(args), stdin=subprocess.DEVNULL, capture_output=True)
    for d in rw:
        if mnt("--bind", d, d).returncode: print("CONFINE_FAIL bind", d); sys.exit(97)
    todo = confine_plan(open("/proc/self/mountinfo").read(), rw)
    if "/" not in todo: print("CONFINE_FAIL no root mount"); sys.exit(97)
    for m in todo:
        if mnt("-o", "remount,bind,ro", m).returncode and m == "/": print("CONFINE_FAIL remount /"); sys.exit(97)
    for probe in ("/", "/usr/local/bin", "/tmp", "/etc"):   # root itself must now be refused by the kernel (EROFS)
        if os.path.isdir(probe) and probe not in rw:
            try: open(os.path.join(probe, ".confine-%d" % os.getpid()), "w").close(); os.remove(os.path.join(probe, ".confine-%d" % os.getpid())); print("CONFINE_FAIL writable", probe); sys.exit(97)
            except OSError: pass
    for d in rw:
        try: open(os.path.join(d, ".confine-%d" % os.getpid()), "w").close(); os.remove(os.path.join(d, ".confine-%d" % os.getpid()))
        except OSError: print("CONFINE_FAIL candidate dir not writable", d); sys.exit(97)
    cmd = a.rest[1:] if a.rest and a.rest[0] == "--" else a.rest
    if not cmd: print("CONFINE_FAIL no command"); sys.exit(97)
    os.execvp(cmd[0], cmd)

def sandbox_cmd(mode, argv, timeout, tree, home):
    if mode == "none": return list(argv)
    return (["sudo", "-n", "unshare", "--net", "--mount", "--", sys.executable, "-I", os.path.abspath(__file__), "confine", "--tree", tree, "--home", home, "--", "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "env", "-i", "HOME=" + home, "TMPDIR=" + home,
             "PATH=/usr/local/bin:/usr/bin:/bin", "timeout", "-k", "5", str(timeout)] + list(argv))

def tail_text(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); f.seek(max(0, f.tell() - MAX_TAIL)); raw = f.read()
    except OSError: return ""
    s = raw.decode("utf-8", "replace"); s = "".join(c for c in s if c in "\n\t" or 32 <= ord(c) < 127 or ord(c) > 159)
    return re.sub(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", "***", s)[-MAX_TAIL:]

def run_one(rdir, rid, outdir, mode):
    req = jload(os.path.join(rdir, "request.json")); check_request(req, rid)
    tgz = os.path.join(rdir, "cand.tgz")
    if not os.path.isfile(tgz) or os.path.getsize(tgz) > MAX_TAR or sha256(open(tgz, "rb").read()) != req["bundle_sha256"]: raise ValueError("bundle missing, too large or digest mismatch")
    work = tempfile.mkdtemp(prefix="cand-"); tree = os.path.join(work, "tree"); home = os.path.join(work, "home"); os.makedirs(tree); os.makedirs(home)
    safe_extract(tgz, tree)
    if mode == "linux":
        subprocess.run(["sudo", "-n", "chown", "-R", "65534:65534", tree, home], check=True); subprocess.run(["sudo", "-n", "chmod", "755", work], check=True)
    cmd = sandbox_cmd(mode, req["argv"], req["timeout_s"], tree, home); log = os.path.join(work, "out.log"); t0 = time.time(); timed_out = False
    import resource
    def limits(): resource.setrlimit(resource.RLIMIT_FSIZE, (5 * 2**20, 5 * 2**20)); os.setsid()
    with open(log, "wb") as lf:
        p = subprocess.Popen(cmd, cwd=tree, stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT, preexec_fn=limits, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin") if mode == "none" else "/usr/local/bin:/usr/bin:/bin", "HOME": home, "TMPDIR": home})
        try: code = p.wait(timeout=req["timeout_s"] + 15)
        except subprocess.TimeoutExpired:
            timed_out = True
            try: os.killpg(p.pid, signal.SIGKILL)
            except OSError: pass
            code = p.wait()
    if code == 124: timed_out = True
    res = {"schema": "tpicc-test-result-v1", "id": rid, "bundle_sha256": req["bundle_sha256"], "argv_sha256": argv_sha(req["argv"]), "exit_code": int(code) if not timed_out else 124, "timed_out": timed_out,
           "duration_s": round(time.time() - t0, 1), "output_tail": tail_text(log), "run_id": os.environ.get("GITHUB_RUN_ID", "local"), "sandbox": "linux-unshare-net-nobody" if mode == "linux" else "none"}
    os.makedirs(outdir, exist_ok=True); json.dump(res, open(os.path.join(outdir, rid + ".json"), "w"), sort_keys=True)
    if mode == "linux": subprocess.run(["sudo", "-n", "rm", "-rf", work])
    else: shutil.rmtree(work, ignore_errors=True)

def cmd_run(a):
    base = os.path.join(a.records, "requests"); done = 0
    for rid in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if done >= MAX_PER_RUN: break
        if not ID_RE.match(rid) or os.path.exists(os.path.join(a.records, "results", rid + ".json")): continue
        try: run_one(os.path.join(base, rid), rid, a.out, a.sandbox)
        except Exception as e: print("REQUEST_REJECTED %s %s" % (rid, type(e).__name__))   # no result is written: the verifier times the request out
        done += 1
    print("processed", done)

def cmd_publish(a):
    n = 0
    for fn in sorted(os.listdir(a.out)) if os.path.isdir(a.out) else []:
        rid = fn[:-5]
        if not fn.endswith(".json") or not ID_RE.match(rid): print("SKIP", fn); continue
        r = jload(os.path.join(a.out, fn)); rq = os.path.join(a.records, "requests", rid, "request.json")
        ok = (isinstance(r, dict) and set(r) == RES_KEYS and r["schema"] == "tpicc-test-result-v1" and r["id"] == rid and os.path.isfile(rq)
              and SHA_RE.match(str(r["bundle_sha256"])) and SHA_RE.match(str(r["argv_sha256"])) and type(r["exit_code"]) is int and type(r["timed_out"]) is bool
              and isinstance(r["duration_s"], (int, float)) and isinstance(r["output_tail"], str) and len(r["output_tail"]) <= MAX_TAIL and isinstance(r["run_id"], str) and re.fullmatch(r"[0-9a-z]{1,20}", r["run_id"])
              and r["sandbox"] in ("linux-unshare-net-nobody", "none"))
        if not ok: print("REJECT", rid); continue
        req = jload(rq)
        if req["bundle_sha256"] != r["bundle_sha256"] or argv_sha(req["argv"]) != r["argv_sha256"]: print("REJECT_BINDING", rid); continue
        dst = os.path.join(a.records, "results", rid + ".json")
        if os.path.exists(dst): print("EXISTS", rid); continue
        os.makedirs(os.path.dirname(dst), exist_ok=True); json.dump(r, open(dst, "w"), sort_keys=True); n += 1
    print("published", n)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    r = sp.add_parser("run"); r.add_argument("--records", required=True); r.add_argument("--out", required=True); r.add_argument("--sandbox", choices=["linux", "none"], default="linux")
    p = sp.add_parser("publish"); p.add_argument("--out", required=True); p.add_argument("--records", required=True)
    c = sp.add_parser("confine"); c.add_argument("--tree", required=True); c.add_argument("--home", required=True); c.add_argument("rest", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    {"run": cmd_run, "publish": cmd_publish, "confine": cmd_confine}[a.cmd](a)
