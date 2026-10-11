#!/usr/bin/env python3
"""Replay samples/lab-traffic.pcap through Suricata and check which rules fire (needs suricata installed).

    python scripts/test_suricata_rules.py [path/to/suricata.yaml]
"""
import collections
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if not shutil.which("suricata"):
    sys.exit("suricata is not installed: skipping (install it, or load the rules on your lab sensor and use the pcap there)")
cfg = sys.argv[1] if len(sys.argv) > 1 else "/etc/suricata/suricata.yaml"
out = tempfile.mkdtemp()
r = subprocess.run(["suricata", "-r", str(ROOT / "samples/lab-traffic.pcap"), "-S", str(ROOT / "suricata/vulnlab.rules"),
                    "-c", cfg, "-k", "none", "-l", out, "-v"], capture_output=True, text=True)
loaded = [l for l in (r.stdout + r.stderr).splitlines() if "rules successfully loaded" in l]
print(loaded[0].split("detect:")[-1].strip() if loaded else "could not read the rule-load line")
hits = collections.Counter()
for line in (Path(out) / "eve.json").read_text().splitlines():
    e = json.loads(line)
    if e.get("event_type") == "alert":
        port = e["dest_port"] if e["dest_port"] in (8081, 8082) else e["src_port"]
        hits[(e["alert"]["signature_id"], port)] += 1

expect_both = [4100001, 4100010, 4100020, 4100030, 4100040]    # the attempt is visible on both builds
expect_vuln_only = [4100050, 4100060]                          # only the vulnerable build's responses prove success
bad = 0
for sid in expect_both:
    for port in (8081, 8082):
        ok = hits[(sid, port)] > 0
        bad += not ok
        print(("ok   " if ok else "FAIL ") + f"sid {sid} fires on port {port} ({hits[(sid, port)]}x)")
for sid in expect_vuln_only:
    ok = hits[(sid, 8081)] > 0 and hits[(sid, 8082)] == 0
    bad += not ok
    print(("ok   " if ok else "FAIL ") + f"sid {sid} fires only on the vulnerable build (8081: {hits[(sid, 8081)]}x, 8082: {hits[(sid, 8082)]}x)")
exact = {(4100001, 8081): 2, (4100010, 8081): 1, (4100020, 8081): 1}
for k, n in exact.items():
    ok = hits[k] == n
    bad += not ok
    print(("ok   " if ok else "FAIL ") + f"no false positives for sid {k[0]}: exactly {n} alert(s) for the {n} attack request(s) (got {hits[k]})")
print("\nALL SURICATA CHECKS PASSED" if not bad else f"\n{bad} FAILURE(S)")
sys.exit(1 if bad else 0)
