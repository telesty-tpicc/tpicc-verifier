#!/usr/bin/env python3
"""One verifier cycle (DRAFT): poll the work repo for submit/* branches, verify, publish verdicts, mirror the baseline.
Environment (set by the scheduled workflow from repo secrets; tokens are embedded in URLs in memory only and scrubbed from all output):
  WORK_URL REAL_URL LEDGER_URL [RECORDS_URL]  ANCHOR_PATH  ANCHOR_PIN  [MAX_PER_CYCLE]
Public log lines contain only an opaque handle, the attempt number and a verdict code."""
import json, os, sys, tempfile, tpicc_verifier as tv

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
        verdict = v.process(name); body = json.dumps(verdict, indent=1)
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

if __name__ == "__main__":
    e = os.environ
    v = tv.Verifier(e["WORK_URL"], e["REAL_URL"], e["LEDGER_URL"], tempfile.mkdtemp(prefix="verifier-"), e["ANCHOR_PATH"], e["ANCHOR_PIN"], log=lambda s: print(tv.scrub(s)))
    try: run_cycle(v, e.get("RECORDS_URL"), int(e.get("MAX_PER_CYCLE", "20")))
    except Exception as ex:
        print("CYCLE_FAILED %s" % type(ex).__name__); sys.exit(1)
