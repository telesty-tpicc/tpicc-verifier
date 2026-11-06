#!/usr/bin/env python3
"""One verifier cycle for the PLANNING-RECORDS profile (Gate 1, DRAFT, unpublished). Identical to cycle.py except the Verifier is a RecordsVerifier and no
independent test runner is used (records missions carry no test command). Environment: WORK_URL REAL_URL LEDGER_URL [RECORDS_URL] ANCHOR_PATH ANCHOR_PIN [MAX_PER_CYCLE].
REAL_URL must name the disposable records STAND-IN repository, never the canonical TPICC repository (governed publication D3: no automated promotion)."""
import os, sys, tempfile, tpicc_verifier as tv, cycle, records_profile as rp

if __name__ == "__main__":
    e = os.environ
    v = rp.RecordsVerifier(e["WORK_URL"], e["REAL_URL"], e["LEDGER_URL"], tempfile.mkdtemp(prefix="verifier-"), e["ANCHOR_PATH"], e["ANCHOR_PIN"], log=lambda s: print(tv.scrub(s)))
    try: cycle.run_cycle(v, e.get("RECORDS_URL"), int(e.get("MAX_PER_CYCLE", "20")))
    except Exception as ex:
        print("CYCLE_FAILED %s" % type(ex).__name__); sys.exit(1)
