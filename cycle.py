#!/usr/bin/env python3
"""One verifier cycle (DRAFT): poll the work repo for submit/* branches, verify, publish verdicts, mirror the baseline.
Environment (set by the scheduled workflow from repo secrets; tokens are embedded in URLs in memory only and scrubbed from all output):
  WORK_URL REAL_URL LEDGER_URL [RECORDS_URL]  ANCHOR_PATH  ANCHOR_PIN  [MAX_PER_CYCLE]
Public log lines contain only an opaque handle, the attempt number and a verdict code."""
import gzip, io, json, os, sys, tarfile, tempfile, tpicc_verifier as tv

def publish(v, remote, branch, files, create_only=False, retries=8):
    """Write files to `branch` of `remote` using git plumbing only (no checkout). Non-forced push; retries on a lost race."""
    for _ in range(retries):
        tip = None
        p = v.g.run("fetch", "--no-tags", "-q", remote, "+refs/heads/%s:refs/pub/tip" % branch, ok_fail=True)
        if p.returncode == 0:
            if create_only: raise tv.Refuse("REFUSED_UNVERIFIABLE", "branch already exists")
            tip = v.g.run("rev-parse", "refs/pub/tip").stdout.decode().strip()
        idx = os.path.join(v.scratch, "idx-%d" % os.getpid()); env = {"GIT_INDEX_FILE": idx}
        if os.path.exists(idx): os.remove(idx)
        if tip: v.g.run("read-tree", tip, env=env)
        for path, data in files.items():
            if tv.norm_path_problem(path): raise tv.Refuse("REFUSED_UNVERIFIABLE", "bad record path")
            b = v.g.run("hash-object", "-w", "--stdin", input=data if isinstance(data, bytes) else data.encode()).stdout.decode().strip()
            v.g.run("update-index", "--add", "--cacheinfo", "100644,%s,%s" % (b, path), env=env)
        tree = v.g.run("write-tree", env=env).stdout.decode().strip()
        args = ["commit-tree", tree, "-m", "record"] + (["-p", tip] if tip else [])
        c = v.g.run(*args).stdout.decode().strip()
        if v.g.run("push", "-q", remote, "%s:refs/heads/%s" % (c, branch), ok_fail=True).returncode == 0: return c
    raise tv.Refuse("REFUSED_UNVERIFIABLE", "could not publish record")

def list_branches(v, remote, pattern):
    out = v.g.run("ls-remote", "--heads", remote, pattern, ok_fail=True)
    if out.returncode != 0: raise tv.Refuse("REFUSED_UNVERIFIABLE", "cannot list branches")
    return {l.split("\t")[1][len("refs/heads/"):]: l.split("\t")[0] for l in out.stdout.decode().splitlines() if "\t" in l}

def run_cycle(v, records=None, max_per_cycle=20):
    done = []
    subs = list_branches(v, v.work, "refs/heads/submit/*"); have = list_branches(v, v.work, "refs/heads/verdict/*")
    for name in sorted(subs)[:max_per_cycle * 5]:
        m = tv.SUBMIT_RE.match(name)
        if not m or ("verdict/" + name[len("submit/"):]) in have: continue
        if len(done) >= max_per_cycle: break
        verdict = v.process(name)
        if verdict is None: continue   # independent tests still running
        body = json.dumps(verdict, indent=1)
        try:
            publish(v, v.work, "verdict/" + name[len("submit/"):], {"verdict.json": body}, create_only=True)
            if records:
                publish(v, records, "records", {"%s/verdicts/%d.json" % (verdict["handle"], verdict["attempt"]): body})
        except Exception as e:   # a verdict that cannot be delivered is retried next cycle only if no promotion happened; promotion is already ledgered
            v.log("%s %d PUBLISH_FAILED" % (verdict["handle"], verdict["attempt"]))
        done.append((name, verdict["code"]))
    # baseline mirror: workers read current main from the work repo's `base` branch (read-only for them by convention; the verifier overwrites it each cycle)
    try:
        sha = v.real_main()
        v.g.run("push", "-q", v.work, "%s:refs/heads/base" % sha, ok_fail=True)
    except Exception: v.log("MIRROR_FAILED")
    return done

RES_KEYS = {"schema", "id", "bundle_sha256", "argv_sha256", "exit_code", "timed_out", "duration_s", "output_tail", "run_id", "sandbox"}
MAX_BUNDLE = 40 * 2**20

def export_bundle(v, cand):
    """Deterministic tar.gz of the candidate tree without .github/, built from git objects only (nothing is checked out or executed here)."""
    raw = v.g.run("archive", "--format=tar", cand).stdout; buf = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw)) as src, gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as dst:
        for m in src:
            if m.name == ".github" or m.name.startswith(".github/"): continue
            if not (m.isfile() or m.isdir()): raise tv.Refuse("REFUSED_UNVERIFIABLE", "candidate tree contains links or special files; tests cannot run safely")
            dst.addfile(m, src.extractfile(m) if m.isfile() else None)
    out = buf.getvalue()
    if len(out) > MAX_BUNDLE: raise tv.Refuse("REFUSED_LIMIT", "candidate tree too large for the test runner")
    return out

def check_result(v, r, rid, bsha, argv_h):
    ok = (isinstance(r, dict) and set(r) == RES_KEYS and r["schema"] == "tpicc-test-result-v1" and r["id"] == rid and type(r["exit_code"]) is int and type(r["timed_out"]) is bool
          and isinstance(r["output_tail"], str) and isinstance(r["run_id"], str) and isinstance(r["duration_s"], (int, float)) and isinstance(r["sandbox"], str))
    if not ok: raise tv.Refuse("REFUSED_UNVERIFIABLE", "test result malformed")
    if r["bundle_sha256"] != bsha or r["argv_sha256"] != argv_h: raise tv.Refuse("REFUSED_UNVERIFIABLE", "test result does not bind to this candidate tree and signed command")
    if r["sandbox"] not in v.cfg["test_sandboxes"]: raise tv.Refuse("REFUSED_UNVERIFIABLE", "test result came from an unaccepted sandbox mode")
    if r["timed_out"] or r["exit_code"] != 0:
        raise tv.Refuse("REFUSED_TESTS", ("independent tests %s (exit %d): " % ("timed out" if r["timed_out"] else "failed", r["exit_code"])) + r["output_tail"][-380:], fixable=True)
    return {"independent": True, "exit_code": 0, "bundle_sha256": bsha, "runner_run": r["run_id"], "sandbox": r["sandbox"], "duration_s": r["duration_s"]}

def make_tester(records_url):
    """Request an isolated test run through the private records repository, and read the result back. Returns a callable for Verifier(tester=...)."""
    def tester(v, m, cand, handle, attempt):
        rid = "%s-%d" % (handle, attempt); t = m["test"]; bundle = export_bundle(v, cand); bsha = tv.sha256(bundle); argv_h = tv.sha256(json.dumps(t["argv"], separators=(",", ":")).encode())
        if v.g.run("fetch", "--no-tags", "-q", records_url, "+refs/heads/main:refs/rec/main", ok_fail=True).returncode != 0: raise tv.Refuse("REFUSED_UNVERIFIABLE", "test runner repository unavailable")
        res = v.g.run("cat-file", "blob", "refs/rec/main:results/%s.json" % rid, ok_fail=True)
        if res.returncode == 0: return check_result(v, tv.load_json(res.stdout), rid, bsha, argv_h)
        req = v.g.run("cat-file", "blob", "refs/rec/main:requests/%s/request.json" % rid, ok_fail=True)
        if req.returncode != 0:
            body = {"schema": "tpicc-test-request-v1", "id": rid, "bundle_sha256": bsha, "argv": t["argv"], "timeout_s": t["timeout_s"], "requested_at": v.now()}
            publish(v, records_url, "main", {"requests/%s/request.json" % rid: json.dumps(body, sort_keys=True), "requests/%s/cand.tgz" % rid: bundle})
            raise tv.Pending()
        r = tv.load_json(req.stdout)
        if r.get("bundle_sha256") != bsha: raise tv.Refuse("REFUSED_UNVERIFIABLE", "test request does not match the candidate")
        if (tv.parse_ts(v.now()) - tv.parse_ts(r["requested_at"])).total_seconds() > v.cfg["test_wait_s"]:
            raise tv.Refuse("REFUSED_UNVERIFIABLE", "independent tests did not complete in time", fixable=True)
        raise tv.Pending()
    return tester

if __name__ == "__main__":
    e = os.environ
    v = tv.Verifier(e["WORK_URL"], e["REAL_URL"], e["LEDGER_URL"], tempfile.mkdtemp(prefix="verifier-"), e["ANCHOR_PATH"], e["ANCHOR_PIN"], log=lambda s: print(tv.scrub(s)), tester=make_tester(e["RECORDS_URL"]) if e.get("RECORDS_URL") else None)
    try: run_cycle(v, e.get("RECORDS_URL"), int(e.get("MAX_PER_CYCLE", "20")))
    except Exception as ex:
        print("CYCLE_FAILED %s" % type(ex).__name__); sys.exit(1)
