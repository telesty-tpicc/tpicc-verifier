#!/usr/bin/env python3
"""TPICC-GROK-RECORDS-ACCESS-001 Gate 1: hash-gated PLANNING-RECORDS profile (DRAFT, offline, unpublished).

A subclass of the baseline Verifier. A records mission is an Owner-signed STANDING authorization (<= 7 days, max_promotions accepted submissions) that lets
one named principal create and modify planning-state records only. Everything the baseline enforces still applies (signature, anchor pin, expiry, revocation,
nonce replay, attempt limit, baseline descent, fast-forward, per-commit path/op/mode/size, ledger). This module adds:
  * an extended protected-path deny list (the Owner-governed record classes and all executable/web surfaces)
  * two fixed record areas only: work-order files and add-only operational records
  * modify = content-hash precondition (blob id at the signed baseline AND at the current head), front-matter field allowlists, closed value sets
  * operational record schemas (assignment, progress, test-result, blocker, evidence), add-only, attribution fields bound to the mission
  * audit attribution (principal, handle, promotions used) in the verdict; the ledger records handle + candidate digest as before
Candidate content is only ever read as git objects; nothing is checked out or executed."""
import json, re, unicodedata, tpicc_verifier as tv

PROFILE = "records-v1"
SCHEMA = "tpicc-records-mission-v1"
WO_DIR = "engineering/work-orders/"
REC_DIR = "engineering/records/grok/"
KINDS = ("assignment", "progress", "test-result", "blocker", "evidence")
PRINCIPAL_RE = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
WO_FILE_RE = re.compile(r"^engineering/work-orders/([a-z0-9]+(?:-[a-z0-9]+)*-[0-9]{3})\.md$")
REC_FILE_RE = re.compile(r"^engineering/records/grok/(%s)/([a-z0-9]+(?:-[a-z0-9]+)*-[0-9]{3})-([0-9]{1,4})\.json$" % "|".join(KINDS))
MAX_PROMOTIONS = 50
MAX_WO_BYTES = 65536
MAX_REC_BYTES = 16384
MAX_STR = 2000

# Classes no records mission may ever cover (added to the baseline deny list). Prefix match; "/" = directory.
EXTRA_DENY = ["governance/", "AGENTS.md", "CLAUDE.md", ".github/", "engineering/execution-authority/", "engineering/executions/", "engineering/owner-approval/",
              "engineering/lifecycle-receipts/", "engineering/completions/", "engineering/tracks/", "engineering/initiatives/", "engineering/journal/",
              "engineering/deployment-receipts/", "engineering/deployment/", "api/", "bin/", "config/", "tools/verifier/", "js/", "css/", "index.html",
              "verifier/", "runner/", "owner/", "contract/"]

# ---- work-order front-matter policy -------------------------------------------------------------------------------------------------
CREATE_KEYS = {"id", "revision", "title", "track_id", "initiative_id", "sprint_id", "status", "disposition", "priority", "owner", "executor", "reviewer",
               "repository", "related_repository", "branch", "accepted_commit", "product_repository", "product_branch", "product_accepted_commit",
               "last_updated", "deployment_required", "execution_authorized", "depends_on", "risk_class", "delivery_plan", "workcenter_exclusion_reason",
               "safety_envelope_allowed_actions", "safety_envelope_prohibited_actions", "safety_envelope_validation_requirements",
               "safety_envelope_stop_condition", "created_by", "mission"}
MODIFY_KEYS = {"status", "disposition", "priority", "executor", "last_updated", "depends_on"}   # planning-state and assignment metadata only; body edits only inside "## Operational notes"
RISK_OK = {"R0", "R1", "R2", "R3", "R4"}
OPS_HEADING = "## Operational notes"
NULLISH = {"null", "~", ""}
STATUS_OK = {"PLANNING", "READY", "BLOCKED", "PAUSED"}
DISP_OK = {"QUEUED", "DEFERRED"}
PRIORITY_OK = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
def BIDI(t): return any(unicodedata.category(c) in ("Cf", "Zl", "Zp") for c in t)   # bidi/zero-width/line-separator characters can mislead a human reviewer
def ascii_ok(v): return all(0x20 <= ord(c) < 0x7f for c in v)
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
EXEC_RE = re.compile(r"^(agent|[a-z][a-z0-9-]{2,31})$")
DEP_RE = re.compile(r"^(null|[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3})$")
OWNER_NAME = "Bradley Severson"

class FM(Exception): pass

# R1: byte-exact front-matter grammar. Python str.strip()/isspace() remove Unicode whitespace that PHP trim() keeps; a value is therefore never stripped here, and a line whose value has
# leading or trailing whitespace of any kind (ASCII or Unicode) is refused instead of being read two ways.
KEY_RE = re.compile(r"([a-z][a-z0-9_]*):(?: (\S(?:.*\S)?))?")
CONT_RE = re.compile(r"(?:  - |    )\S(?:.*\S)?")
STRICT_VAL = re.compile(r"[!-~](?:[ -~]*[!-~])?")      # printable ASCII, no leading or trailing space: the only form a created or changed value may take

def parse_fm(raw):
    """Strict front matter: '---' line, flat 'key: value' lines with optional '  - item' continuation, '---' line. Returns (dict key->raw block text, body)."""
    # canonical TPICC (PHP) splits lines with preg_split('/\\R/') WITHOUT /u: CR, VT, FF and the raw byte 0x85 are line breaks there but not here. Refuse every such byte anywhere in the file.
    if any(b in raw for b in (b"\r", b"\x0b", b"\x0c", b"\x85")): raise FM("line-break bytes the canonical parser treats differently (CR, VT, FF, 0x85)")
    try: t = raw.decode("utf-8")
    except UnicodeDecodeError: raise FM("not UTF-8")
    if CTRL.search(t) or BIDI(t): raise FM("control or format characters")
    if not t.startswith("---\n"): raise FM("no front matter")
    end = t.find("\n---\n", 4)
    if end < 0: raise FM("front matter not closed")
    head, body = t[4:end], t[end + 5:]
    blocks, cur = {}, None
    for line in head.split("\n"):
        if CONT_RE.fullmatch(line):
            if cur is None: raise FM("orphan continuation")
            blocks[cur] += "\n" + line; continue
        m = KEY_RE.fullmatch(line)
        if not m: raise FM("unparseable front matter line")   # R1: exactly one ASCII space after the colon, value with no leading or trailing whitespace of any kind (Unicode included)
        if m.group(1) in blocks: raise FM("duplicate key")
        cur = m.group(1); blocks[cur] = m.group(2) or ""      # R1: the raw value, never stripped or unquoted
    return blocks, body

def ops_split(body):
    """(before, ops, after): the operational-notes section runs from its '## Operational notes' line to the next '## ' heading or the end. ops is None when absent."""
    lines = body.split("\n"); i = next((k for k, l in enumerate(lines) if l.rstrip() == OPS_HEADING), None)
    if i is None: return body, None, ""
    j = next((k for k in range(i + 1, len(lines)) if lines[k].startswith("## ")), len(lines))
    return "\n".join(lines[:i]), "\n".join(lines[i:j]), "\n".join(lines[j:])

def scalar(v):
    """R1: exact raw value. No stripping and no quote removal: PHP fm_scalar trims different characters, removes one matching quote pair only, and types true/false/null/integers, so a value is only accepted
    when it is byte-for-byte one of the closed literals a check compares against ("false", "null", "1", a status name)."""
    return v

# R4: agent-authored text must not look like an Owner-sanctioned section. canonical rules (phase_clarification_named_paths) treat '## Owner clarification' bodies as Owner-sanctioned, and humans read
# Owner/approval/authority headings as Owner decisions. A created body may therefore carry no heading (ATX at any indentation, setext, or HTML) whose text names those sections;
# inside the operational-notes section of an existing order no heading-like line may be added at all.
RESERVED_HEADING = re.compile(r"owner|authori[sz]|approv|ratif|clarif|decision|execution|authority|accept|delivery[ _]plan|stop[ _]condition|safety[ _]envelope|sealed|baseline", re.I)
SETEXT_RE = re.compile(r" {0,3}(?:=+|-+)[ \t]*")
HTML_H_RE = re.compile(r"\s*<h[1-6]\b", re.I)
def is_heading_like(line): return line.lstrip(" \t").startswith("#") or bool(SETEXT_RE.fullmatch(line)) or bool(HTML_H_RE.match(line))
def reserved_headings(body):
    L = body.split("\n"); out = []
    for i, l in enumerate(L):
        s = l.lstrip(" \t")
        if s.startswith("#"): text = s.lstrip("#")
        elif HTML_H_RE.match(l): text = re.sub(r"<[^>]*>", " ", l)
        elif l.strip() and i + 1 < len(L) and SETEXT_RE.fullmatch(L[i + 1]): text = l
        else: continue
        if RESERVED_HEADING.search(text): out.append(l.strip()[:60])
    return out

def check_wo_create(path, raw, principal, handle):
    fm, body = parse_fm(raw)
    rh = reserved_headings(body)
    if rh: raise FM("created body has a heading that impersonates an Owner-sanctioned section: %r" % rh[0])
    stem = WO_FILE_RE.match(path).group(1)
    extra = set(fm) - CREATE_KEYS
    if extra: raise FM("keys outside the create allowlist: %s" % ",".join(sorted(extra)))
    for k in ("id", "title", "status", "disposition", "execution_authorized", "created_by", "mission", "revision", "risk_class"):
        if k not in fm: raise FM("missing required key " + k)
    if scalar(fm["id"]) != stem.upper(): raise FM("id must be the upper-case file name stem, exactly")
    if scalar(fm["status"]) not in {"PLANNING", "READY"}: raise FM("status must start as PLANNING or READY")
    if scalar(fm["disposition"]) not in DISP_OK: raise FM("disposition outside QUEUED/DEFERRED")
    if scalar(fm["execution_authorized"]) != "false": raise FM("execution_authorized must be false")
    for k in ("accepted_commit", "product_accepted_commit", "branch"):
        if k in fm and fm[k] != "null": raise FM(k + " must be the literal null on creation")
    if "priority" in fm and scalar(fm["priority"]) not in PRIORITY_OK: raise FM("priority outside the closed set")
    if scalar(fm["revision"]) != "1": raise FM("a new work order must declare revision 1")
    if scalar(fm["risk_class"]) not in RISK_OK: raise FM("explicit risk_class R0-R4 required")
    for k, v in fm.items():
        if len(v) > 4000: raise FM("front matter value too long (field %s)" % k)
        for i, ln in enumerate(v.split("\n")):
            if not STRICT_VAL.fullmatch(ln if i == 0 else ln.lstrip(" ")) and not (i == 0 and ln == ""): raise FM("front matter value must be printable ASCII without leading or trailing space (field %s)" % k)
    if scalar(fm.get("owner", OWNER_NAME)) != OWNER_NAME or scalar(fm.get("reviewer", OWNER_NAME)) != OWNER_NAME: raise FM("owner and reviewer must be the Owner")
    if "executor" in fm and not EXEC_RE.match(scalar(fm["executor"])): raise FM("executor outside the allowed grammar")
    if "last_updated" in fm and not DATE_RE.match(scalar(fm["last_updated"])): raise FM("last_updated must be YYYY-MM-DD")
    if "depends_on" in fm and not DEP_RE.match(scalar(fm["depends_on"])): raise FM("depends_on must be null or a work-order id")
    if "delivery_plan" in fm:
        try: dp = tv.load_json(fm["delivery_plan"].encode())
        except Exception: raise FM("delivery_plan must be one JSON object without duplicate keys")
        if not isinstance(dp, dict): raise FM("delivery_plan must be a JSON object")
        if dp.get("deploy") is not None: raise FM("a new work order may not name a deploy block")
        if "risk_class" in dp and dp["risk_class"] != scalar(fm["risk_class"]): raise FM("delivery_plan risk_class differs from risk_class")
        al = dp.get("allowlist", [])
        if not (isinstance(al, list) and all(isinstance(a, str) and tv.norm_path_problem(a.rstrip("/")) is None and not any(tv.overlaps(a, d) for d in tv.DEFAULT_CONFIG["deny"] + EXTRA_DENY) for a in al)): raise FM("delivery_plan allowlist reaches a protected class or is malformed")
    if BIDI(raw.decode("utf-8")): raise FM("control or format characters")
    if "deployment_required" in fm and scalar(fm["deployment_required"]) != "false": raise FM("deployment_required must be false on creation")
    if scalar(fm["created_by"]) != principal or scalar(fm["mission"]) != handle: raise FM("attribution does not match the mission")
    if len(raw) > MAX_WO_BYTES: raise FM("work order too large")

def check_wo_modify(old_raw, new_raw, principal, handle):
    o, ob = parse_fm(old_raw); n, nb = parse_fm(new_raw)
    if len(new_raw) > MAX_WO_BYTES: raise FM("work order too large")
    ob_pre, ob_ops, ob_post = ops_split(ob); nb_pre, nb_ops, nb_post = ops_split(nb)
    if ob_ops is None:
        if nb_ops is not None and not (nb_pre.rstrip("\n") == ob.rstrip("\n") and nb_post == ""): raise FM("body changed outside the operational-notes section")
        if nb_ops is None and nb != ob: raise FM("body changed outside the operational-notes section")
    elif nb_ops is None or nb_pre != ob_pre or nb_post != ob_post: raise FM("body changed outside the operational-notes section")
    if ob_ops is not None and nb_ops is not None and nb_ops != ob_ops:
        # append-only, and an appended block must start after a blank line: text glued to the last existing line would extend it (markdown lazy continuation), and the old text may end without a newline
        keep = ob_ops.rstrip("\n") + "\n\n"; tail = nb_ops[len(keep):].lstrip("\n")
        if not nb_ops.startswith(keep) or tail[:1] in (" ", "\t"): raise FM("operational notes are append-only: the existing notes must stay exactly as they are and new text must start in a new block after a blank line")
    if nb_ops is not None and BIDI(nb_ops): raise FM("control or format characters in operational notes")
    if nb_ops is not None:
        import collections
        added = collections.Counter(nb_ops.split("\n")) - collections.Counter((ob_ops or "").split("\n"))
        if any(is_heading_like(l) and l.rstrip() != OPS_HEADING for l in added): raise FM("operational notes may not add a heading-like line")
    if nb_ops is not None and len(nb_ops.encode()) > 8192: raise FM("operational notes section too large")
    for k in set(o) | set(n):
        if o.get(k) != n.get(k):
            if k not in MODIFY_KEYS: raise FM("field %s may not be changed" % k)
            v = scalar(n.get(k, ""))
            if k in n and (not STRICT_VAL.fullmatch(v) or "\n" in v): raise FM("field %s: value must be one printable ASCII line without leading or trailing space" % k)
            if k == "last_updated" and not DATE_RE.match(v): raise FM("last_updated must be YYYY-MM-DD")
            if k == "executor" and not EXEC_RE.match(v): raise FM("executor outside the allowed grammar")
            if k == "depends_on" and not DEP_RE.match(v): raise FM("depends_on must be null or a work-order id")
    if o.get("status") != n.get("status"):
        if scalar(o.get("status", "")) not in STATUS_OK: raise FM("status transition from a non-planning state")
        if scalar(n.get("status", "")) not in STATUS_OK: raise FM("status outside PLANNING/READY/BLOCKED/PAUSED")
    if o.get("disposition") != n.get("disposition"):
        if scalar(o.get("disposition", "")) not in DISP_OK or scalar(n.get("disposition", "")) not in DISP_OK: raise FM("disposition outside QUEUED/DEFERRED")
    if "priority" in n and o.get("priority") != n.get("priority") and scalar(n["priority"]) not in PRIORITY_OK: raise FM("priority outside the closed set")
    # a work order that carries authority or any non-planning state is never editable by this profile, whatever the diff
    for src in (o, n):
        if scalar(src.get("execution_authorized", "false")) != "false": raise FM("work order is execution-authorized")
        if scalar(src.get("status", "")) not in STATUS_OK: raise FM("work order is not in a planning state")
        if scalar(src.get("disposition", "")) not in DISP_OK: raise FM("work order disposition is not QUEUED/DEFERRED")

# ---- operational records ------------------------------------------------------------------------------------------------------------
COMMON = {"schema", "kind", "work_order", "recorded_by", "mission", "recorded_at", "seq"}
KIND_FIELDS = {
    "assignment": {"assignee", "role", "note"},
    "progress": {"summary", "percent"},
    "test-result": {"suite", "passed", "failed", "summary", "commit"},
    "blocker": {"summary", "needs"},
    "evidence": {"title", "sha256", "location", "note"},
}
KIND_REQUIRED = {"assignment": {"assignee"}, "progress": {"summary"}, "test-result": {"suite", "passed", "failed"}, "blocker": {"summary"}, "evidence": {"title", "sha256"}}
WO_ID_RE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$")

def check_record(path, raw, principal, handle):
    if len(raw) > MAX_REC_BYTES: raise FM("record too large")
    try: r = tv.load_json(raw)
    except Exception: raise FM("record is not valid JSON")
    m = REC_FILE_RE.match(path); kind, wo_stem, seq = m.group(1), m.group(2), int(m.group(3))
    if not isinstance(r, dict): raise FM("record is not an object")
    extra = set(r) - COMMON - KIND_FIELDS[kind]
    if extra: raise FM("fields outside the record schema: %s" % ",".join(sorted(extra)))
    if not (COMMON | KIND_REQUIRED[kind]) <= set(r): raise FM("missing required fields")
    if r["schema"] != "tpicc-grok-record-v1" or r["kind"] != kind or r["seq"] != seq: raise FM("schema, kind or sequence mismatch")
    if not (isinstance(r["work_order"], str) and WO_ID_RE.match(r["work_order"]) and r["work_order"].lower() == wo_stem): raise FM("work_order does not match the file name")
    if r["recorded_by"] != principal or r["mission"] != handle: raise FM("attribution does not match the mission")
    if not (isinstance(r["recorded_at"], str) and tv.TS_RE.match(r["recorded_at"])): raise FM("bad timestamp")
    for k, v in r.items():
        if isinstance(v, str):
            if len(v) > MAX_STR or CTRL.search(v.replace("\n", " ")) or BIDI(v) or "\r" in v: raise FM("string field invalid: " + k)
        elif k in ("passed", "failed", "percent", "seq"):
            if type(v) is not int or v < 0 or v > 10**9 or (k == "percent" and v > 100): raise FM("numeric field invalid: " + k)
        else: raise FM("unsupported value type: " + k)
    if kind == "evidence" and not re.fullmatch(r"[0-9a-f]{64}", r["sha256"]): raise FM("sha256 must be 64 hex characters")
    if kind == "test-result" and "commit" in r and not tv.SHA_RE.match(r["commit"]): raise FM("commit must be a 40-hex id")

class RecordsVerifier(tv.Verifier):
    SCHEMAS = (SCHEMA,)
    EXTRA_KEYS = frozenset({"profile", "principal", "max_promotions", "preconditions"})
    def __init__(self, *a, **kw):
        cfg = dict(kw.pop("config", None) or {})
        cfg["deny"] = list(tv.DEFAULT_CONFIG["deny"]) + EXTRA_DENY
        cfg["enforcement"] = list(tv.DEFAULT_CONFIG["enforcement"]) + ["engineering/execution-authority/", "engineering/tracks/", "CLAUDE.md"]
        kw["config"] = cfg; super().__init__(*a, **kw); self.caps = {}
    # a records mission may be used until max_promotions accepted submissions; the baseline's one-shot 'complete' rule is replaced by a count
    def _exhausted(self, handle, rows):
        return sum(1 for r in rows if r[1] == "complete" and r[2] == handle) >= self.caps.get(handle, 1)
    # accepted records advance the head inside allow_paths; those moves are governed by the content-hash preconditions, so only footprint/enforcement/WO are watched
    def watch_paths(self, m): return m["footprint"] + [m["wo_path"]] + self.cfg["enforcement"]
    def load_mission(self, handle):
        m, tip = super().load_mission(handle)
        pr = m["principal"]
        if m["profile"] != PROFILE or not (isinstance(pr, str) and PRINCIPAL_RE.match(pr)): raise tv.Refuse("REFUSED_UNVERIFIABLE", "records mission profile or principal invalid")
        if not (type(m["max_promotions"]) is int and 1 <= m["max_promotions"] <= MAX_PROMOTIONS): raise tv.Refuse("REFUSED_UNVERIFIABLE", "max_promotions out of range")
        if m["risk"] != "R1" or "test" in m: raise tv.Refuse("REFUSED_UNVERIFIABLE", "records missions are R1 and carry no test command")
        for e in m["allow_paths"]:
            if not (e.startswith(WO_DIR) or e.startswith(REC_DIR)): raise tv.Refuse("REFUSED_UNVERIFIABLE", "records mission path outside the two record areas")
        pc = m["preconditions"]
        if not (isinstance(pc, dict) and all(isinstance(k, str) and tv.SHA_RE.match(str(v)) and any(tv.under(k, a) for a in m["allow_paths"]) and WO_FILE_RE.match(k) for k, v in pc.items())):
            raise tv.Refuse("REFUSED_UNVERIFIABLE", "preconditions malformed or outside allow_paths")
        if m["wo_path"] in pc: raise tv.Refuse("REFUSED_UNVERIFIABLE", "the pinned planning work order may not be a modify target")
        self.caps[handle] = m["max_promotions"]
        return m, tip
    def verify_candidate(self, name, handle, attempt, cand_sha_hint=None):
        m, nonce_h, cand, real, base = super().verify_candidate(name, handle, attempt, cand_sha_hint)
        principal, reasons, codes = m["principal"], [], set()
        if len([x for x in self.g.run("rev-list", "%s..%s" % (real, cand)).stdout.decode().split() if x]) != 1: raise tv.Refuse("REFUSED_LIMIT", "a records candidate must be exactly one commit", fixable=True)
        for r in [x for x in self.g.run("rev-list", "%s..%s" % (real, cand)).stdout.decode().split() if x]:
            msg = self.g.run("log", "-n1", "--format=%B", r).stdout.decode()
            if ("Mission: " + handle) not in [l.strip() for l in msg.splitlines()]: raise tv.Refuse("REFUSED_FIELD", "commit %s lacks the 'Mission: %s' trailer" % (r[:8], handle), fixable=True)
        def bad(code, why): codes.add(code); reasons.append(why[:160])
        for om, nm, st, paths, osha, nsha in self.changes(real, cand):   # net change the promotion would make
            p = paths[-1]
            if nm != "100644": bad("REFUSED_MODE", "%s: only regular non-executable files (100644)" % p); continue
            if st == "A":
                if WO_FILE_RE.match(p):
                    try: check_wo_create(p, self.g.run("cat-file", "blob", nsha).stdout, principal, handle)
                    except FM as e: bad("REFUSED_FIELD", "%s: %s" % (p, e))
                elif REC_FILE_RE.match(p):
                    try: check_record(p, self.g.run("cat-file", "blob", nsha).stdout, principal, handle)
                    except FM as e: bad("REFUSED_FIELD", "%s: %s" % (p, e))
                else: bad("REFUSED_PATH", "%s does not match a record file pattern" % p)
            elif st == "M":
                if not WO_FILE_RE.match(p): bad("REFUSED_OP", "%s: operational records are add-only" % p); continue
                want = m["preconditions"].get(p)
                if want is None: bad("REFUSED_PRECONDITION", "%s has no signed content-hash precondition" % p); continue
                bp = self.g.run("rev-parse", "%s:%s" % (base, p), ok_fail=True)
                if bp.returncode != 0 or bp.stdout.decode().strip() != want: bad("REFUSED_PRECONDITION", "%s differs from the signed baseline hash" % p); continue
                if osha != want: bad("REFUSED_PRECONDITION", "%s changed on the current head since the signed baseline" % p); continue
                try: check_wo_modify(self.g.run("cat-file", "blob", osha).stdout, self.g.run("cat-file", "blob", nsha).stdout, principal, handle)
                except FM as e: bad("REFUSED_FIELD", "%s: %s" % (p, e))
            else: bad("REFUSED_OP", "operation %s on %s is not allowed" % (st, p))
        for c in ("REFUSED_MODE", "REFUSED_PRECONDITION", "REFUSED_FIELD", "REFUSED_PATH", "REFUSED_OP"):
            if c in codes: raise tv.Refuse(c, "; ".join(sorted(set(reasons)))[:600], fixable=True)
        return m, nonce_h, cand, real, base
    def act_intent(self, handle, nonce_h, digest):
        # R2: the baseline refuses an intent when a revoke row already exists (checked against the fresh tip inside the append). A revoke row that lands AFTER our intent row is read here,
        # immediately before the push, and turns the promotion into an abort. The remaining window (between this read and the push) is closed by the Owner script, which waits for every open
        # act-intent of the handle to close (complete or abort) before it reports the revocation as quiesced.
        row = super().act_intent(handle, nonce_h, digest)
        if any(r[1] == "revoke" and r[2] == handle for r in self.ledger.state()[1]):
            self.ledger.append("abort", handle, nonce_h, "promote", digest)
            raise tv.Refuse("REFUSED_REVOKED", "mission revoked before the push")
        return row
    def promote(self, name, m, nonce_h, cand, real):
        # F9: re-check signature, expiry and revocation immediately before the claim/act-intent (narrows the verify-to-push window)
        mm, tip = self.load_mission(m["handle"]); self.check_revocation(m["handle"], tip)
        if any(r[1] == "revoke" and r[2] == m["handle"] for r in self.ledger.state()[1]): raise tv.Refuse("REFUSED_REVOKED", "mission revoked")
        return super().promote(name, m, nonce_h, cand, real)
    def process(self, name):
        v = super().process(name)
        if v and v.get("code") == "ACCEPTED":
            try:
                m = self.load_mission(v["handle"])[0]; used = sum(1 for r in self.ledger.state()[1] if r[1] == "complete" and r[2] == v["handle"])
                v["attribution"] = {"principal": m["principal"], "profile": PROFILE, "promotions_used": used, "promotions_max": m["max_promotions"]}
            except Exception: pass
        return v
