#!/usr/bin/env python3
"""Offline check of wazuh/vulnlab_rules.xml against real VulnLab log lines.

This is a small EMULATOR of the Wazuh rule features used in this file (decoded_as json, field regex, if_sid,
if_matched_sid + frequency/timeframe, same_field, same_source_ip). It catches typos and logic mistakes before
you load the rules, but it is NOT Wazuh. The definitive test is wazuh-logtest on your manager (see the docs).

  python scripts/test_wazuh_rules.py <log.json> [<log.json> ...]    # print the winning rule for each line
  python scripts/test_wazuh_rules.py --selftest <vulnerable.json> <patched.json>
"""
import calendar
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / "wazuh" / "vulnlab_rules.xml"


def load_rules():
    rules = []
    for r in ET.parse(RULES).getroot().iter("rule"):
        rules.append({
            "id": r.get("id"), "level": int(r.get("level")), "desc": (r.findtext("description") or "").strip(),
            "if_sid": r.findtext("if_sid"), "if_matched_sid": r.findtext("if_matched_sid"),
            "freq": int(r.get("frequency", 0)), "timeframe": int(r.get("timeframe", 0)),
            "same_field": r.findtext("same_field"), "same_ip": r.find("same_source_ip") is not None,
            "decoded_as": r.findtext("decoded_as"),
            "fields": [(f.get("name"), f.get("type") or "osregex", f.text) for f in r.findall("field")],
        })
    return rules


def val(v):
    return "true" if v is True else "false" if v is False else str(v)


def fields_match(rule, ev):
    for name, _kind, pattern in rule["fields"]:
        if name not in ev or not re.search(pattern, val(ev[name])):
            return False
    return True


def evaluate(events):
    """Return, for each event, the list of rule dicts that fired."""
    rules = load_rules()
    by_id = {r["id"]: r for r in rules}
    history = {}                                    # parent rule id -> list of (epoch, event)
    results = []
    for ev in events:
        t = calendar.timegm(time.strptime(ev["ts"], "%Y-%m-%dT%H:%M:%SZ"))
        matched = {}

        def fire(rule):                              # does this rule match the event (ignoring frequency)?
            if rule["id"] in matched:
                return matched[rule["id"]]
            ok = True
            parent = rule["if_sid"] or rule["if_matched_sid"]
            if parent:
                ok = fire(by_id[parent])
            if ok:
                ok = fields_match(rule, ev)
            matched[rule["id"]] = ok
            return ok

        for rule in rules:
            if not rule["freq"]:
                fire(rule)
        for rule in rules:                           # frequency rules
            if not rule["freq"]:
                continue
            parent = by_id[rule["if_matched_sid"]]
            if not fire(parent):
                continue
            history.setdefault(parent["id"], []).append((t, ev))
            recent = [e for (ts, e) in history[parent["id"]] if t - ts <= rule["timeframe"]]
            if rule["same_field"]:
                recent = [e for e in recent if e.get(rule["same_field"]) == ev.get(rule["same_field"])]
            if rule["same_ip"]:
                recent = [e for e in recent if e.get("srcip") == ev.get("srcip")]
            matched[rule["id"]] = len(recent) >= rule["freq"]
        results.append([by_id[i] for i, ok in matched.items() if ok])
    return results


def winner(fired):
    fired = [r for r in fired if r["level"] > 0]
    return max(fired, key=lambda r: (r["level"], r["id"])) if fired else None


def read(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def selftest(vuln_path, patched_path):
    bad = 0

    def check(label, ok):
        nonlocal bad
        print(("ok   " if ok else "FAIL ") + label)
        bad += (not ok)

    for variant, path in (("vulnerable", vuln_path), ("patched", patched_path)):
        events = read(path)
        res = evaluate(events)

        def first(pred):
            for ev, f in zip(events, res):
                if pred(ev):
                    return winner(f)

        def rid(w):
            return w["id"] if w else None

        print(f"\n== {variant} build ({len(events)} log lines)")
        check("normal login by priya raises no alert", rid(first(lambda e: e["event"] == "login_success" and e["params"] == "username=priya&password=priya123")) is None)
        check("own order (1001) raises no alert", rid(first(lambda e: e.get("order_id") == 1001)) is None)
        check("health check raises no alert", rid(first(lambda e: e["path"] == "/healthz")) is None)
        check("wrong-password login -> 100150", rid(first(lambda e: e["params"] == "username=admin&password=guess0")) == "100150")
        check("6th failed login within 60s -> 100151 (brute force)", any(rid(winner(f)) == "100151" for f in res))
        check("SQLi payload recognised (100110 / 100111)", rid(first(lambda e: "admin' --" in e["params"])) in ("100110", "100111"))
        check("order of another user -> 100140/100141", rid(first(lambda e: e.get("order_id") == 1002)) in ("100140", "100141"))
        check("enumeration -> 100142", any(rid(winner(f)) == "100142" for f in res))
        check("XSS payload -> 100121", rid(first(lambda e: "<script>" in e["params"])) == "100121")
        check("command injection payload recognised (100130 / 100131)", rid(first(lambda e: e["path"] == "/tools/lookup" and ";" in e["params"])) in ("100130", "100131"))
        if variant == "vulnerable":
            check("SQLi login bypass SUCCEEDED -> 100111 (level 13)", rid(first(lambda e: "admin' --" in e["params"])) == "100111")
            check("tautology bypass SUCCEEDED -> 100111", rid(first(lambda e: "' OR '1'='1" in e["params"])) == "100111")
            check("cross-user order returned -> 100141", rid(first(lambda e: e.get("order_id") == 1002)) == "100141")
            check("command injection returned 200 -> 100131 (level 13)", rid(first(lambda e: e["path"] == "/tools/lookup" and ";" in e["params"])) == "100131")
        else:
            check("SQLi attempt did NOT succeed (no 100111)", not any(rid(winner(f)) == "100111" for f in res))
            check("cross-user order was refused (403) -> 100140 only", rid(first(lambda e: e.get("order_id") == 1002)) == "100140")
            check("command injection was refused (400) -> 100130 only", rid(first(lambda e: e["path"] == "/tools/lookup" and ";" in e["params"])) == "100130")
    print("\nALL SELF-TESTS PASSED" if not bad else f"\n{bad} FAILURE(S)")
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--selftest":
        sys.exit(selftest(sys.argv[2], sys.argv[3]))
    for p in sys.argv[1:]:
        evs = read(p)
        for ev, f in zip(evs, evaluate(evs)):
            w = winner(f)
            label = (w["id"] + " L" + str(w["level"])) if w else "--"
            print(f"{label:10} {ev['method']} {ev['path']} {ev['params'][:60]!r} -> {w['desc'][:70] if w else 'no alert'}")
