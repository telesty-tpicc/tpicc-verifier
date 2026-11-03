#!/usr/bin/env python3
"""TPICC P1 rehearsal verifier (DRAFT, unpublished). Python 3.9+ stdlib, git and ssh-keygen only.

Treats every agent-submitted commit as untrusted DATA: it never checks out, never runs hooks/filters/submodule code and never executes any
file from a candidate. It reads only git objects (plumbing), under a scrubbed environment. Any exception or unverifiable condition fails
closed: nothing is promoted and the verdict is REFUSED_UNVERIFIABLE (or the narrower code). Public output is verdict codes + opaque handle only.
"""
import datetime, hashlib, json, os, re, subprocess, sys, tempfile, shutil, unicodedata

MISSION_NS = "tpicc-mission-authorization-v1"
REVOKE_NS = "tpicc-mission-revocation-v1"
HANDLE_RE = re.compile(r"^[0-9a-f]{16}$")
SUBMIT_RE = re.compile(r"^submit/([0-9a-f]{16})-([0-9]{1,3})$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FIELD_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
LEDGER_TYPES = ("claim", "act-intent", "revoke", "complete", "abort")
ZERO = "0" * 64
DEFAULT_CONFIG = {
    # paths no mission may ever cover (prefix match on a normalised path; a trailing "/" means a directory)
    "deny": ["governance/", ".github/", "AGENTS.md", "engineering/owner-approval/", "bin/owner-approve.php", "api/deployment/providers/",
             ".gitattributes", ".gitmodules", "tools/verifier/"],
    # files whose change between the signed baseline and the current head is material even if outside the footprint
    "enforcement": ["governance/", "AGENTS.md", "engineering/owner-approval/", "bin/owner-approve.php", "tools/verifier/"],
    "max_commits": 50, "max_files": 20, "max_blob": 262144, "max_validity_days": 7, "intent_ttl_s": 600,
    "test_wait_s": 1800, "test_sandboxes": ["linux-unshare-net-nobody"],   # P3: how long to wait for the independent test result; runner sandbox modes the verifier accepts
}

def scrub(t):
    """remove credentials embedded in URLs from any text before it can reach an error message or log"""
    return re.sub(r"(://)[^/@\s]+@", r"\1***@", t)

class Pending(Exception):
    """the independent test result is not available yet: no verdict, no ledger entry, try again next cycle"""

class Refuse(Exception):
    def __init__(self, code, reason, fixable=False):
        Exception.__init__(self, reason); self.code, self.reason, self.fixable = code, reason, fixable

def now_iso(): return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
def parse_ts(s): return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
def sha256(b): return hashlib.sha256(b).hexdigest()

def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise ValueError("duplicate key")
        d[k] = v
    return d
def load_json(b): return json.loads(b.decode("utf-8"), object_pairs_hook=_no_dups)

class Git:
    """Scrubbed git: no system/global config, no hooks, no prompts, no external diff/textconv, no recursion into submodules."""
    def __init__(self, repo, home, allow_file=False, token_env=None):
        self.repo, self.home, self.allow_file = repo, home, allow_file
    def env(self):
        e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"), "HOME": self.home, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
             "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "LC_ALL": "C", "GIT_AUTHOR_NAME": "tpicc-verifier", "GIT_AUTHOR_EMAIL": "verifier@invalid",
             "GIT_COMMITTER_NAME": "tpicc-verifier", "GIT_COMMITTER_EMAIL": "verifier@invalid"}
        for k in ("GIT_HTTP_EXTRAHEADER",):
            if k in os.environ: e[k] = os.environ[k]
        return e
    def run(self, *args, **kw):
        cfg = ["-c", "core.hooksPath=" + os.devnull, "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=" + ("always" if self.allow_file else "never"),
               "-c", "core.fsmonitor=false", "-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true", "-c", "credential.helper=", "-c", "diff.external=", "-c", "core.attributesFile=" + os.devnull]
        cmd = ["git"] + cfg + (["--git-dir", self.repo] if self.repo else []) + list(args)
        env = self.env(); env.update(kw.pop("env", {}))
        p = subprocess.run(cmd, input=kw.get("input"), capture_output=True, env=env, timeout=kw.get("timeout", 120))
        if p.returncode != 0 and not kw.get("ok_fail"):
            raise RuntimeError("git %s failed: %s" % (args[0], scrub(p.stderr.decode("utf-8", "replace"))[:200]))
        return p

def norm_path_problem(path):
    """Return a reason string if a repo path is not acceptable, else None. ASCII-only, no dot segments, no .git (any case), no control chars."""
    if not path or len(path) > 200: return "empty or over-long path"
    if not re.fullmatch(r"[A-Za-z0-9._/@+=,-]+", path): return "path outside the printable ASCII set"
    if path.startswith("/") or path.endswith("/") or "//" in path: return "malformed path"
    for seg in path.split("/"):
        if seg in (".", "..") or seg.lower().startswith(".git"):
            return "git-internal or dot-segment path"
    return None

def under(path, entry):
    """entry ending in "/" is a directory prefix; any other entry is that exact file. Case-insensitive."""
    p, e = path.lower(), entry.lower()
    return p == e or (e.endswith("/") and p.startswith(e))

def overlaps(a, d):
    """does mission entry `a` (file or dir) overlap protected entry `d`?"""
    return under(a, d) or under(d, a) or (d.endswith("/") and (a.rstrip("/") + "/").lower().startswith(d.lower()))

def parse_raw(out):
    """git diff-tree -r -z --raw output -> [(oldmode,newmode,status,[paths])]"""
    parts = out.split(b"\0"); i, res = 0, []
    while i < len(parts) and parts[i]:
        meta = parts[i].decode().lstrip(":").split(" "); st = meta[4]; n = 2 if st[0] in "RC" else 1
        res.append((meta[0], meta[1], st[0], [p.decode("utf-8", "replace") for p in parts[i + 1:i + 1 + n]], meta[2], meta[3])); i += 1 + n
    return res

class Ledger:
    """Linear hash chain on one branch; a non-forced push is the compare-and-swap. Entries hold opaque fields only (lint-enforced)."""
    def __init__(self, git, remote, branch="ledger/claims", retries=12, clock=None):
        self.g, self.remote, self.branch, self.retries, self.clock = git, remote, branch, retries, clock or now_iso
    def _fetch(self):
        p = self.g.run("fetch", "--no-tags", "-q", self.remote, "+refs/heads/%s:refs/ledger/tip" % self.branch, ok_fail=True)
        if p.returncode != 0: raise Refuse("REFUSED_UNVERIFIABLE", "ledger unreachable")
    def _read(self):
        self._fetch()
        tip = self.g.run("rev-parse", "refs/ledger/tip").stdout.decode().strip()
        txt = self.g.run("cat-file", "blob", tip + ":chain.log", ok_fail=True)
        return tip, (txt.stdout.decode() if txt.returncode == 0 else "")
    @staticmethod
    def entry_hash(prev, f): return sha256(("|".join([prev] + f)).encode())
    @staticmethod
    def lint(f):
        t, h, nh, action, digest, actor, ts = f[1], f[2], f[3], f[4], f[5], f[6], f[7]
        if t not in LEDGER_TYPES or actor not in ("verifier", "owner") or not TS_RE.match(ts): return False
        return all(FIELD_RE.match(x) for x in (t, h, nh, action, digest, actor)) and HANDLE_RE.match(h) is not None and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    def parse(self, txt):
        rows, prev = [], ZERO
        for i, line in enumerate([l for l in txt.split("\n") if l]):
            c = line.split("|")
            if len(c) != 10 or int(c[0]) != i + 1 or c[8] != prev or c[9] != self.entry_hash(prev, c[:8]) or not self.lint(c[:8]):
                raise Refuse("REFUSED_UNVERIFIABLE", "ledger chain invalid at line %d" % (i + 1))
            rows.append(c); prev = c[9]
        return rows
    def state(self):
        tip, txt = self._read(); return tip, self.parse(txt)
    def append(self, type_, handle, nonce_h, action, digest, actor="verifier", check=None, ts=None):
        """check(rows)->None to proceed, or raise Refuse. Returns the appended row. Evaluated again on every retry against the fresh tip."""
        for _ in range(self.retries):
            tip, rows = self.state()
            if check: check(rows)
            seq = len(rows) + 1; prev = rows[-1][9] if rows else ZERO
            f = [str(seq), type_, handle, nonce_h, action, digest, actor, ts or self.clock()]
            if not self.lint(f): raise Refuse("REFUSED_UNVERIFIABLE", "ledger lint refused the entry")
            row = f + [prev, self.entry_hash(prev, f)]
            blob = self.g.run("hash-object", "-w", "--stdin", input=(self._txt(rows) + "|".join(row) + "\n").encode()).stdout.decode().strip()
            tree = self.g.run("mktree", input=("100644 blob %s\tchain.log\n" % blob).encode()).stdout.decode().strip()
            commit = self.g.run("commit-tree", tree, "-p", tip, "-m", "ledger %d" % seq).stdout.decode().strip()
            p = self.g.run("push", "-q", self.remote, "%s:refs/heads/%s" % (commit, self.branch), ok_fail=True)   # never forced
            if p.returncode == 0: return row
            self._fetch()
            if self.g.run("rev-parse", "refs/ledger/tip").stdout.decode().strip() == tip:   # tip unchanged: a rule refused us, not a lost race
                raise Refuse("REFUSED_UNVERIFIABLE", "ledger push refused")
        raise Refuse("REFUSED_UNVERIFIABLE", "ledger contention")
    @staticmethod
    def _txt(rows): return "".join("|".join(r) + "\n" for r in rows)

def verify_sig(data, sig, signers, namespace, principal="owner"):
    d = tempfile.mkdtemp()
    try:
        for n, b in (("s", signers), ("g", sig)): open(os.path.join(d, n), "wb").write(b)
        p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", os.path.join(d, "s"), "-I", principal, "-n", namespace, "-s", os.path.join(d, "g")], input=data, capture_output=True, timeout=30)
        return p.returncode == 0
    finally: shutil.rmtree(d, ignore_errors=True)

class Verifier:
    def __init__(self, work, real, ledger, scratch, anchor_path, anchor_pin, config=None, allow_file=False, now=None, records=None, log=print, tester=None):
        self.cfg = dict(DEFAULT_CONFIG); self.cfg.update(config or {})
        self.scratch = scratch; os.makedirs(scratch, exist_ok=True)
        self.home = tempfile.mkdtemp(dir=scratch)   # empty HOME: no user/global git config, no credential helpers
        bare = os.path.join(scratch, "objects.git"); Git(None, self.home).run("init", "--bare", "-q", bare)
        self.g = Git(bare, self.home, allow_file=allow_file); self.work, self.real = work, real
        self.now = now or now_iso; self.ledger = Ledger(self.g, ledger, clock=self.now); self.anchor_path, self.anchor_pin = anchor_path, anchor_pin
        self.records, self.log, self.tester = records, log, tester
    # ---- reading remote data as objects only ----
    def fetch(self, remote, ref, local):
        p = self.g.run("fetch", "--no-tags", "--no-recurse-submodules", "-q", remote, "+%s:%s" % (ref, local), ok_fail=True)
        if p.returncode != 0: raise Refuse("REFUSED_UNVERIFIABLE", "cannot fetch %s" % ref)
        return self.g.run("rev-parse", local).stdout.decode().strip()
    def blob(self, rev, path):
        p = self.g.run("cat-file", "blob", "%s:%s" % (rev, path), ok_fail=True)
        if p.returncode != 0: raise Refuse("REFUSED_UNVERIFIABLE", "missing %s" % path)
        return p.stdout
    def is_anc(self, a, b): return self.g.run("merge-base", "--is-ancestor", a, b, ok_fail=True).returncode == 0
    def changes(self, a, b):
        return parse_raw(self.g.run("diff-tree", "-r", "-z", "--raw", "-M", "-C", "--no-ext-diff", "--no-textconv", "--find-renames", a, b).stdout)
    # ---- mission ----
    def load_mission(self, handle):
        tip = self.fetch(self.work, "refs/heads/owner/%s" % handle, "refs/m/%s" % handle)
        raw, sig = self.blob(tip, "mission.json"), self.blob(tip, "mission.json.sig")
        anchor = self.blob(self.real_main(), self.anchor_path)
        if sha256(anchor) != self.anchor_pin: raise Refuse("REFUSED_UNVERIFIABLE", "trust anchor does not match its pin")
        if not verify_sig(raw, sig, anchor, MISSION_NS): raise Refuse("REFUSED_SIGNATURE", "mission signature did not verify")
        try: m = load_json(raw)
        except Exception: raise Refuse("REFUSED_UNVERIFIABLE", "mission is not valid JSON")
        need = {"schema", "handle", "work_order", "wo_path", "wo_sha256", "risk", "baseline", "allow_paths", "allowed_ops", "footprint", "max_attempts", "nonce", "issued_at", "expires_at"}
        if isinstance(m, dict) and "test" in m: need = need | {"test"}   # P3: optional signed test command
        if not isinstance(m, dict) or set(m) != need or m["schema"] != "tpicc-mission-v1" or m["handle"] != handle or m["risk"] not in ("R1", "R2"):
            raise Refuse("REFUSED_UNVERIFIABLE", "mission malformed or ineligible risk class")
        if not (isinstance(m["allow_paths"], list) and m["allow_paths"] and all(isinstance(x, str) for x in m["allow_paths"]) and isinstance(m["footprint"], list)
                and isinstance(m["allowed_ops"], list) and set(m["allowed_ops"]) <= {"A", "M"} and isinstance(m["max_attempts"], int) and 0 < m["max_attempts"] <= 20
                and isinstance(m["nonce"], str) and re.fullmatch(r"[0-9a-f]{32}", m["nonce"]) and SHA_RE.match(str(m["baseline"])) and re.fullmatch(r"[0-9a-f]{64}", str(m["wo_sha256"]))
                and TS_RE.match(str(m["issued_at"])) and TS_RE.match(str(m["expires_at"]))):
            raise Refuse("REFUSED_UNVERIFIABLE", "mission field values invalid")
        for e in m["allow_paths"] + m["footprint"]:
            if not isinstance(e, str) or norm_path_problem(e.rstrip("/")): raise Refuse("REFUSED_UNVERIFIABLE", "mission lists an unacceptable path")
        for e in m["allow_paths"]:
            if any(overlaps(e, d) for d in self.cfg["deny"]): raise Refuse("REFUSED_UNVERIFIABLE", "mission covers a class that is never eligible")
        if "test" in m:
            t = m["test"]; a = t.get("argv") if isinstance(t, dict) else None
            if not (isinstance(t, dict) and set(t) == {"argv", "timeout_s"} and isinstance(a, list) and 2 <= len(a) <= 6 and a[0] in ("php", "python3", "node") and (a[0] != "node" or (len(a) == 2 and re.fullmatch(r"[A-Za-z0-9._/-]+\.c?js", a[1]) is not None)) and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9._/=-]{1,100}", x) for x in a)
                    and not any(x.startswith("-") or x.startswith("/") or ".." in x.split("/") for x in a[1:]) and isinstance(t["timeout_s"], int) and 10 <= t["timeout_s"] <= 300
                    and any(under(a[1], p) for p in m["allow_paths"])):
                raise Refuse("REFUSED_UNVERIFIABLE", "mission test command is outside policy")
        iss, exp, now = parse_ts(m["issued_at"]), parse_ts(m["expires_at"]), parse_ts(self.now())
        if exp - iss > datetime.timedelta(days=self.cfg["max_validity_days"]) or exp <= iss: raise Refuse("REFUSED_UNVERIFIABLE", "validity window invalid")
        if now >= exp: raise Refuse("REFUSED_EXPIRED", "mission expired")
        if iss > now + datetime.timedelta(minutes=5): raise Refuse("REFUSED_UNVERIFIABLE", "mission issued in the future")
        return m, tip
    def real_main(self): return self.fetch(self.real, "refs/heads/main", "refs/real/main")
    # ---- one submission ----
    def check_revocation(self, handle, tip):
        """Owner-signed revoke on owner/<handle> -> ledger revoke entry (idempotent)."""
        p = self.g.run("cat-file", "blob", tip + ":revoke.json", ok_fail=True)
        if p.returncode != 0: return
        sig = self.g.run("cat-file", "blob", tip + ":revoke.json.sig", ok_fail=True)
        anchor = self.blob(self.real_main(), self.anchor_path)
        if sha256(anchor) != self.anchor_pin or sig.returncode != 0 or not verify_sig(p.stdout, sig.stdout, anchor, REVOKE_NS): return   # forged revoke: ignored
        try: r = load_json(p.stdout)
        except Exception: return
        if not isinstance(r, dict) or r.get("handle") != handle: return
        def chk(rows):
            if any(x[1] == "revoke" and x[2] == handle for x in rows): raise Refuse("IDEMPOTENT", "already revoked")
        try: self.ledger.append("revoke", handle, "0" * 32, "revoke", sha256(p.stdout), actor="owner", check=chk)
        except Refuse as e:
            if e.code != "IDEMPOTENT": raise
    def verify_candidate(self, name, handle, attempt, cand_sha_hint=None):
        m, mtip = self.load_mission(handle)
        self.check_revocation(handle, mtip)
        nonce_h = sha256(m["nonce"].encode())[:32]
        _, rows = self.ledger.state()
        if any(r[1] == "revoke" and r[2] == handle for r in rows): raise Refuse("REFUSED_REVOKED", "mission revoked")
        if any(r[1] == "complete" and r[2] == handle for r in rows): raise Refuse("REFUSED_REPLAY", "mission already completed")
        if any(r[1] == "claim" and r[3] == nonce_h and r[2] != handle for r in rows): raise Refuse("REFUSED_REPLAY", "nonce already used by another mission")
        if attempt > m["max_attempts"]: raise Refuse("REFUSED_ATTEMPTS", "attempt limit reached")
        cand = self.fetch(self.work, "refs/heads/submit/%s-%d" % (handle, attempt), "refs/cand/%s-%d" % (handle, attempt))
        real = self.real_main(); base = m["baseline"]
        if self.g.run("cat-file", "-e", base + "^{commit}", ok_fail=True).returncode != 0: raise Refuse("BASELINE_MATERIAL", "signed baseline is not part of the current head's history")
        wo = self.blob(base, m["wo_path"])
        if sha256(wo) != m["wo_sha256"]: raise Refuse("REFUSED_UNVERIFIABLE", "work order digest does not match the baseline")
        # baseline rule: head descends from the signed baseline; a change to footprint/dependencies/enforcement files is material
        if not self.is_anc(base, real): raise Refuse("BASELINE_MATERIAL", "current head does not descend from the signed baseline")
        watch = m["footprint"] + m["allow_paths"] + [m["wo_path"]] + self.cfg["enforcement"]
        moved = [p for c in self.changes(base, real) for p in c[3] if any(under(p, w) for w in watch)]
        if moved: raise Refuse("BASELINE_MATERIAL", "head changed signed-scope files: %d path(s)" % len(moved))
        if not self.is_anc(real, cand) or cand == real: raise Refuse("NEEDS_REBASE", "candidate is not a fast-forward of the current head", fixable=True)
        revs = [x for x in self.g.run("rev-list", "--reverse", "--topo-order", "%s..%s" % (real, cand)).stdout.decode().split() if x]
        if len(revs) > self.cfg["max_commits"]: raise Refuse("REFUSED_LIMIT", "too many commits", fixable=True)
        if self.g.run("rev-list", "--merges", "%s..%s" % (real, cand)).stdout.strip(): raise Refuse("REFUSED_OP", "merge commits are not allowed", fixable=True)
        reasons, codes, files = [], set(), set()
        for r in revs:
            for om, nm, st, paths, osha, nsha in self.changes(r + "^", r):
                for p in paths:
                    files.add(p); prob = norm_path_problem(p)
                    if prob: codes.add("REFUSED_PATH"); reasons.append("%s: %s" % (p, prob)); continue
                    if any(under(p, d) for d in self.cfg["deny"]): codes.add("REFUSED_PATH"); reasons.append("%s is in a protected class" % p); continue
                    if not any(under(p, a) for a in m["allow_paths"]): codes.add("REFUSED_PATH"); reasons.append("%s is outside allow_paths" % p)
                if st not in m["allowed_ops"]: codes.add("REFUSED_OP"); reasons.append("operation %s on %s is not allowed" % (st, paths[-1]))
                if nm not in ("100644", "100755", "000000") or om not in ("000000", "100644", "100755"): codes.add("REFUSED_MODE"); reasons.append("mode %s/%s on %s" % (om, nm, paths[-1]))
                elif nm != "000000" and int(self.g.run("cat-file", "-s", nsha).stdout) > self.cfg["max_blob"]: codes.add("REFUSED_LIMIT"); reasons.append("%s exceeds the size limit" % paths[-1])
        if len(files) > self.cfg["max_files"]: codes.add("REFUSED_LIMIT"); reasons.append("too many files")
        for c in ("REFUSED_MODE", "REFUSED_PATH", "REFUSED_OP", "REFUSED_LIMIT"):
            if c in codes: raise Refuse(c, "; ".join(sorted(set(reasons)))[:600], fixable=True)
        return m, nonce_h, cand, real, base
    def act_intent(self, handle, nonce_h, digest):
        def intent_chk(rows):   # re-run on every retry against the fresh tip: this is the revoke/act ordering gate
            mine = [r for r in rows if r[2] == handle]
            if not any(r[1] == "claim" for r in mine): raise Refuse("REFUSED_UNVERIFIABLE", "act without claim")
            if any(r[1] == "revoke" for r in mine): raise Refuse("REFUSED_REVOKED", "mission revoked")
            if any(r[1] == "complete" for r in mine): raise Refuse("REFUSED_REPLAY", "mission already completed")
            opened = [r for r in mine if r[1] == "act-intent"]; closed = [r for r in mine if r[1] in ("complete", "abort")]
            if len(opened) > len(closed): raise Refuse("REFUSED_UNVERIFIABLE", "an earlier act-intent is still open")
        return self.ledger.append("act-intent", handle, nonce_h, "promote", digest, check=intent_chk)
    def promote(self, name, m, nonce_h, cand, real):
        handle = m["handle"]; digest = sha256((handle + ":" + cand).encode())
        def claim_chk(rows):
            if any(r[1] == "revoke" and r[2] == handle for r in rows): raise Refuse("REFUSED_REVOKED", "mission revoked")
            if any(r[1] == "claim" and r[3] == nonce_h and r[2] != handle for r in rows): raise Refuse("REFUSED_REPLAY", "nonce already used")
        if not any(r[1] == "claim" and r[2] == handle for r in self.ledger.state()[1]):
            self.ledger.append("claim", handle, nonce_h, "claim", digest, check=claim_chk)
        self.act_intent(handle, nonce_h, digest)
        p = self.g.run("push", "-q", self.real, "%s:refs/heads/main" % cand, ok_fail=True)   # fast-forward only, never forced
        landed = self.g.run("ls-remote", self.real, "refs/heads/main", ok_fail=True).stdout.decode().split("\t")[0]
        if p.returncode != 0 or landed != cand:
            self.ledger.append("abort", handle, nonce_h, "promote", digest)
            raise Refuse("REFUSED_UNVERIFIABLE", "promotion did not land")
        self.ledger.append("complete", handle, nonce_h, "promote", digest)
    def reconcile(self, handle):
        """Close an act-intent left open by a crash: complete if the head already contains the intent's commit, else abort. (Digest only: the
        verifier cannot invert it, so it re-derives from the submission branches it can still see.)"""
        _, rows = self.ledger.state()
        mine = [r for r in rows if r[2] == handle]
        if len([r for r in mine if r[1] == "act-intent"]) <= len([r for r in mine if r[1] in ("complete", "abort")]): return "NOTHING"
        intent = [r for r in mine if r[1] == "act-intent"][-1]
        age = (parse_ts(self.now()) - parse_ts(intent[7])).total_seconds()
        if age < self.cfg["intent_ttl_s"]: return "OPEN"
        real = self.real_main()
        for r in self.g.run("for-each-ref", "--format=%(objectname)", "refs/cand/").stdout.decode().split():
            if sha256((handle + ":" + r).encode()) == intent[5] and self.is_anc(r, real):
                self.ledger.append("complete", handle, intent[3], "promote", intent[5]); return "COMPLETED"
        self.ledger.append("abort", handle, intent[3], "promote", intent[5]); return "ABORTED"
    def process(self, name):
        """name = 'submit/<handle>-<n>' -> verdict dict. Never raises: any failure is a refusal; nothing is promoted unless every check passed."""
        mt = SUBMIT_RE.match(name)
        v = {"schema": "tpicc-verdict-v1", "handle": mt.group(1) if mt else "0" * 16, "attempt": int(mt.group(2)) if mt else 0, "code": "REFUSED_UNVERIFIABLE", "fixable": False, "reasons": ["unverifiable"], "decided_at": self.now()}
        try:
            if not mt: raise Refuse("REFUSED_UNVERIFIABLE", "malformed submission name")
            handle, attempt = mt.group(1), int(mt.group(2))
            m, nonce_h, cand, real, base = self.verify_candidate(name, handle, attempt)
            tests = None
            if "test" in m:   # P3: candidate code is never run here; an isolated runner reports, and the result must bind to exactly this tree
                if self.tester is None: raise Refuse("REFUSED_UNVERIFIABLE", "mission requires independent tests and no runner is configured")
                tests = self.tester(self, m, cand, handle, attempt)
            self.promote(name, m, nonce_h, cand, real)
            v.update({"code": "ACCEPTED", "fixable": False, "reasons": [], "promoted": cand})
            if tests: v["tests"] = tests
        except Pending: return None   # no verdict yet
        except Refuse as e:
            v.update({"code": e.code, "fixable": e.fixable, "reasons": [e.reason[:600]]})
        except Exception as e:   # fail closed
            v.update({"code": "REFUSED_UNVERIFIABLE", "fixable": False, "reasons": ["internal error: %s" % type(e).__name__]})
        self.log("%s %d %s" % (v["handle"], v["attempt"], v["code"]))   # public log line: opaque handle and code only
        return v

if __name__ == "__main__":
    print("library module; see test_verifier.py", file=sys.stderr)
