"""Add CWE / MITRE ATT&CK / OWASP badges under every numbered vulnerability heading
and regenerate docs/tag-index.md. Safe to re-run (idempotent).

Run from the repo root:  python tools/vuln_tags.py

Mappings are best-fit. ATT&CK describes attacker behaviour, so many weaknesses have no clean
technique: those are left blank on purpose. Verify at cwe.mitre.org / attack.mitre.org before quoting.
"""
import re, pathlib
from markdown.extensions.toc import slugify

DOCS = pathlib.Path("docs")
ATTACK_NAMES = {
    "T1190": "Exploit Public-Facing Application", "T1059": "Command and Scripting Interpreter",
    "T1059.007": "JavaScript", "T1195": "Supply Chain Compromise",
    "T1195.001": "Compromise Software Dependencies and Development Tools",
    "T1195.002": "Compromise Software Supply Chain", "T1110": "Brute Force",
    "T1499": "Endpoint Denial of Service", "T1087": "Account Discovery",
    "T1528": "Steal Application Access Token", "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files", "T1552.005": "Cloud Instance Metadata API",
    "T1552.007": "Container API", "T1557": "Adversary-in-the-Middle", "T1040": "Network Sniffing",
    "T1203": "Exploitation for Client Execution", "T1574.001": "DLL Search Order Hijacking",
    "T1611": "Escape to Host", "T1610": "Deploy Container", "T1496": "Resource Hijacking",
    "T1204.003": "Malicious Image", "T1530": "Data from Cloud Storage",
    "T1565.001": "Stored Data Manipulation", "T1584.001": "Compromise Infrastructure: Domains",
    "T1098": "Account Manipulation", "T1136.003": "Create Account: Cloud Account",
    "T1078": "Valid Accounts", "T1068": "Exploitation for Privilege Escalation",
}
# page -> number -> (CWE ids, ATT&CK ids, OWASP label)
D = {
 "part-1-web": {
  1: ([1021], [], ""), 2: ([78], ["T1190", "T1059"], "OWASP A03:2021"),
  3: ([1395], ["T1190"], "OWASP A06:2021"), 4: ([352], [], "OWASP A01:2021"),
  5: ([22], ["T1190"], "OWASP A01:2021"), 6: ([79], ["T1059.007"], "OWASP A03:2021"),
  7: ([425, 862], [], "OWASP A01:2021"), 8: ([113], [], "OWASP A03:2021"),
  9: ([639], [], "OWASP A01:2021"), 10: ([601], [], "OWASP A01:2021"),
  11: ([489], [], "OWASP A05:2021"), 12: ([917, 502], ["T1190"], "OWASP A06:2021"),
  13: ([598], [], ""), 14: ([79], ["T1059.007"], "OWASP A03:2021"),
  15: ([506], ["T1195.002"], "OWASP A08:2021"), 16: ([918], ["T1190", "T1552.005"], "OWASP A10:2021"),
  17: ([384], [], "OWASP A07:2021"), 18: ([89], ["T1190"], "OWASP A03:2021"),
  19: ([79], ["T1059.007"], "OWASP A03:2021"), 20: ([79], [], "OWASP A03:2021"),
  21: ([598], ["T1528"], ""), 22: ([204], ["T1087"], "OWASP A07:2021"),
  23: ([269, 863], [], "OWASP A01:2021"), 24: ([330, 338], [], "OWASP A02:2021"),
  25: ([91], [], "OWASP A03:2021"),
 },
 "part-2-api": {
  1: ([285, 862], [], "OWASP API5:2019"), 2: ([639], [], "OWASP API1:2019"),
  3: ([287, 307], ["T1110"], "OWASP API2:2019"), 4: ([78], ["T1190", "T1059"], "OWASP API8:2019"),
  5: ([200], [], "OWASP API3:2019"), 6: ([], [], "OWASP API9:2019"),
  7: ([778], [], "OWASP API10:2019"), 8: ([770, 400], ["T1499", "T1110"], "OWASP API4:2019"),
  9: ([915], [], "OWASP API6:2019"), 10: ([16, 209, 1188], [], "OWASP API7:2019"),
  11: ([942], [], "OWASP API7:2019"), 12: ([89], ["T1190"], "OWASP API8:2019"),
  13: ([611], ["T1190"], "OWASP API8:2019"),
 },
 "part-3-llm": {
  1: ([1427], [], "OWASP LLM01:2025"), 2: ([200], [], "OWASP LLM02:2025"),
  3: ([1395], [], "OWASP LLM03:2025"), 4: ([], [], "OWASP LLM04:2025"),
  5: ([116], [], "OWASP LLM05:2025"), 6: ([], [], "OWASP LLM06:2025"),
  7: ([200], [], "OWASP LLM07:2025"), 8: ([200, 862], [], "OWASP LLM08:2025"),
  9: ([], [], "OWASP LLM09:2025"), 10: ([400, 770], [], "OWASP LLM10:2025"),
 },
 "part-4-android-ios": {
  1: ([798], ["T1552.001"], "OWASP Mobile M1:2024"), 2: ([1395, 829], ["T1195.001"], "OWASP Mobile M2:2024"),
  3: ([287, 862], [], "OWASP Mobile M3:2024"), 4: ([20], [], "OWASP Mobile M4:2024"),
  5: ([319, 295], ["T1557", "T1040"], "OWASP Mobile M5:2024"), 6: ([359], [], "OWASP Mobile M6:2024"),
  7: ([693], [], "OWASP Mobile M7:2024"), 8: ([489, 926], [], "OWASP Mobile M8:2024"),
  9: ([312, 922], [], "OWASP Mobile M9:2024"), 10: ([327, 321, 916], [], "OWASP Mobile M10:2024"),
  11: ([319, 295], ["T1557"], "OWASP Mobile M5:2024"), 12: ([312, 922], [], "OWASP Mobile M9:2024"),
  13: ([312, 922], [], "OWASP Mobile M9:2024"), 14: ([525], [], "OWASP Mobile M9:2024"),
  15: ([939], [], "OWASP Mobile M4:2024"), 16: ([459], [], "OWASP Mobile M9:2024"),
  17: ([287, 603], [], "OWASP Mobile M3:2024"), 18: ([532], [], "OWASP Mobile M9:2024"),
  19: ([295], ["T1557"], "OWASP Mobile M5:2024"), 20: ([306], [], "OWASP Mobile M3:2024"),
 },
 "part-5-docker": {
  1: ([770], ["T1499", "T1496"], ""), 2: ([250, 269], ["T1611", "T1610"], ""),
  3: ([1395], ["T1611", "T1068"], ""), 4: ([732], ["T1611"], ""),
  5: ([319], ["T1195"], ""), 6: ([1395], [], ""),
  7: ([250, 269], ["T1611"], ""), 8: ([798, 312], ["T1552.001"], ""),
  9: ([668], [], ""), 10: ([494, 829], ["T1204.003"], ""),
 },
 "part-6-aws": {
  1: ([1395], ["T1195.001"], ""), 2: ([532], [], ""), 3: ([78], ["T1059"], ""),
  4: ([611], ["T1190"], ""), 5: ([915, 269], ["T1098"], ""),
  6: ([284], ["T1136.003"], ""), 7: ([16], [], ""),
  8: ([732, 284], ["T1565.001"], ""), 9: ([732, 200], ["T1530"], ""),
  10: ([22], ["T1530"], ""), 11: ([918], ["T1552.005", "T1190"], ""),
  12: ([], ["T1584.001"], ""), 13: ([434, 770], [], ""),
 },
 "part-7-desktop": {
  1: ([78, 89], ["T1059"], ""), 2: ([287, 613], [], ""), 3: ([311, 312], ["T1552.001"], ""),
  4: ([327, 321, 330], [], ""), 5: ([285, 732], ["T1068"], ""),
  6: ([16, 427, 1188], ["T1574.001"], ""), 7: ([319, 295], ["T1040", "T1557"], ""),
  8: ([120, 787, 416, 134, 190], ["T1203"], ""), 9: ([1395], ["T1203"], ""),
  10: ([778], [], ""),
 },
 "part-8-frontend": {
  1: ([352], [], "OWASP A01:2021"), 2: ([79], ["T1059.007"], "OWASP A03:2021"),
  3: ([1336, 79], [], "OWASP A03:2021"), 4: ([79, 116], [], "OWASP A03:2021"),
  5: ([79], ["T1059.007"], "OWASP A03:2021"), 6: ([1395], ["T1195.001"], "OWASP A06:2021"),
 },
 "part-9-kubernetes": {
  1: ([287], ["T1078"], "OWASP K8s K06"), 2: ([778], [], "OWASP K8s K05"),
  3: ([250], ["T1611"], "OWASP K8s K01"), 4: ([], [], "OWASP K8s K04"),
  5: ([16], ["T1190"], "OWASP K8s K09"), 6: ([668], [], "OWASP K8s K07"),
  7: ([269, 250], ["T1078"], "OWASP K8s K03"), 8: ([312, 798], ["T1552.007"], "OWASP K8s K08"),
  9: ([1395], ["T1195"], "OWASP K8s K02"), 10: ([1395], ["T1068"], "OWASP K8s K10"),
 },
}
PAGE_TITLES = {
 "part-1-web": "1. Web", "part-2-api": "2. API", "part-3-llm": "3. LLM",
 "part-4-android-ios": "4. Android and iOS", "part-5-docker": "5. Docker", "part-6-aws": "6. AWS",
 "part-7-desktop": "7. Desktop", "part-8-frontend": "8. Front-end", "part-9-kubernetes": "9. Kubernetes",
}
H2 = re.compile(r"^## (\d+)\. (.+)$")

def cwe_url(n): return f"https://cwe.mitre.org/data/definitions/{n}.html"
def atk_url(t):
    a, _, b = t.partition(".")
    return f"https://attack.mitre.org/techniques/{a}/" + (f"{b}/" if b else "")

def badge_line(cwe, atk, owasp):
    parts = []
    for n in cwe:
        parts.append(f'<a class="vtag cwe" href="{cwe_url(n)}" target="_blank" rel="noopener noreferrer">CWE-{n}</a>')
    for t in atk:
        parts.append(f'<a class="vtag atk" href="{atk_url(t)}" target="_blank" rel="noopener noreferrer" title="{ATTACK_NAMES[t]}">ATT&amp;CK {t}</a>')
    if owasp:
        parts.append(f'<span class="vtag owasp">{owasp}</span>')
    return '<p class="vuln-tags">' + " ".join(parts) + "</p>" if parts else ""

rows, tagged, total = [], 0, 0
for page, items in D.items():
    path = DOCS / f"{page}.md"
    out, in_fence = [], False
    for ln in path.read_text().splitlines():
        if ln.strip().startswith("```"):
            in_fence = not in_fence
        if not in_fence and ln.startswith('<p class="vuln-tags"'):
            if out and out[-1] == "":
                out.pop()
            continue
        out.append(ln)
        m = None if in_fence else H2.match(ln)
        if m:
            num, title = int(m.group(1)), m.group(2).strip()
            cwe, atk, owasp = items[num]
            total += 1
            line = badge_line(cwe, atk, owasp)
            if line:
                tagged += 1
                out += ["", line]
            anchor = slugify(f"{num}. {title}", "-")
            rows.append((page, num, title, anchor, cwe, atk, owasp))
    path.write_text("\n".join(out) + "\n")
    missing = set(items) - {r[1] for r in rows if r[0] == page}
    assert not missing, (page, missing)

def cell_cwe(c): return ", ".join(f"[CWE-{n}]({cwe_url(n)})" for n in c) or "-"
def cell_atk(a): return ", ".join(f"[{t}]({atk_url(t)})" for t in a) or "-"
idx = ["# Tag index", "",
 "Every vulnerability in this guide mapped to the standards employers and tools use: "
 "**CWE** (the weakness type), **MITRE ATT&CK** (how attackers use it) and an **OWASP** category where one fits. "
 "Use the search box or your browser's find (Ctrl+F) to look up a CWE or technique ID.", "",
 '!!! warning "Read this before quoting a mapping"', "",
 "    These are best-fit mappings. ATT&CK describes attacker behaviour, so many weaknesses have no clean technique: those show `-`. "
 "Check the linked CWE / ATT&CK page before you cite one in a report or interview.", "",
 f"**{total}** vulnerabilities, **{tagged}** with at least one tag.", ""]
for page, title in PAGE_TITLES.items():
    idx += [f"## {title}", "", "| # | Vulnerability | CWE | ATT&CK | OWASP |", "|---|---|---|---|---|"]
    for p, num, t, anchor, cwe, atk, owasp in rows:
        if p == page:
            idx.append(f"| {num} | [{t}]({page}.md#{anchor}) | {cell_cwe(cwe)} | {cell_atk(atk)} | {owasp or '-'} |")
    idx.append("")
(DOCS / "tag-index.md").write_text("\n".join(idx))
print(f"headings processed: {total}, with tags: {tagged}")
