# Local lab: VulnLab and detections

The browser [labs](labs/index.md) are simulations. This is the real thing, run **on your own machine**: a small intentionally vulnerable web app and a patched build of the same app, plus **Wazuh** and **Suricata** rules that detect the attacks.

!!! danger "Local use only"

    VulnLab is **intentionally vulnerable**, and the command-injection endpoint really runs shell commands. Run it only on a lab machine or VM you control, never on a shared or production host, and never publish its ports to a network. The compose file binds both builds to `127.0.0.1` and hardens the containers (non-root user, read-only filesystem, all Linux capabilities dropped, memory/CPU/process limits). Only test systems you own or have written permission to test.

## What is in the lab

| Part | What it is |
|---|---|
| `lab/app` | One Flask app, two builds chosen by `VARIANT`: **vulnerable** (port 8081) and **patched** (port 8082) |
| `lab/scripts/run_attacks.py` | Runs the attacks against both builds and shows a pass/fail table |
| `lab/wazuh/vulnlab_rules.xml` | 13 custom Wazuh rules (IDs 100100 to 100151) |
| `lab/suricata/vulnlab.rules` | 8 Suricata rules (SIDs 4100001 to 4100060) |
| `lab/samples/` | Real log lines from both builds and a replayable packet capture |

The four vulnerabilities match the browser labs: **SQL injection** (`/login`), **reflected XSS** (`/search`), **IDOR** (`/api/orders/<id>`) and **command injection** (`/tools/lookup`).

## 1. Start the lab

Requires Docker with Docker Compose.

```bash
cd lab
docker compose up --build -d
python3 scripts/run_attacks.py --check
```

Expected result: every attack is **EXPLOITED** on the vulnerable build and **blocked** on the patched build, and normal login still works on both.

| Attack | Vulnerable build | Patched build |
|---|---|---|
| SQL injection (comment out password) | EXPLOITED | blocked |
| SQL injection (tautology) | EXPLOITED | blocked |
| Reflected XSS | EXPLOITED | blocked |
| IDOR (read another user's order) | EXPLOITED | blocked |
| Command injection | EXPLOITED | blocked |

Add `--noisy` to also brute-force the login and enumerate order IDs, which triggers the correlation rules. Stop and clean up with `docker compose down -v`.

## 2. What the patched build changes

| Vulnerability | Vulnerable build | Patched build |
|---|---|---|
| SQL injection | Input is concatenated into the SQL text | Parameterized query and a password-hash check |
| XSS | Input is placed in the HTML as-is | Output encoding, plus `Content-Security-Policy: script-src 'none'` and `nosniff` |
| IDOR | Any logged-in user can read any order | Ownership check, `403` for other users' orders |
| Command injection | `getent hosts <input>` run through a shell | Allow-list validation and an argument list with no shell |

## 3. Detect with Wazuh

Every request becomes one JSON log line (path, parameters, status, user, event type, and for orders the object owner and a `cross_user_access` flag). Logging the owner is what makes IDOR detectable.

On the machine running the containers (with the Wazuh agent), add the contents of `lab/wazuh/ossec-localfile.xml` inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then restart the agent. On the Wazuh manager:

```bash
sudo cp vulnlab_rules.xml /var/ossec/etc/rules/vulnlab_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/vulnlab_rules.xml
sudo chmod 660 /var/ossec/etc/rules/vulnlab_rules.xml
sudo systemctl restart wazuh-manager
```

**Test before trusting it.** Run `sudo /var/ossec/bin/wazuh-logtest`, paste a line from `lab/samples/vulnerable.json`, and check that the output shows the expected rule in the *filtering* phase.

| Rule | Level | Fires when |
|---|---|---|
| 100110 | 8 | SQL injection pattern in request parameters |
| **100111** | **13** | A login **succeeded** with an injection pattern (the bypass worked) |
| 100112 | 9 | Database error returned from `/login` |
| 100120 / 100121 | 8 / 10 | XSS pattern in parameters / the request returned HTTP 200 |
| 100130 / **100131** | 10 / **13** | Shell metacharacter in `host` / the request returned HTTP 200 |
| 100140 / 100141 | 7 / 10 | A user requested another user's order / it was returned |
| **100142** | **12** | One user hit 5+ other users' orders in 60 seconds (enumeration) |
| 100150 / **100151** | 3 / **10** | Failed login / 6+ failed logins from one source in 60 seconds (brute force) |

Compare the two builds in the dashboard: the patched build still produces the *attempt* alerts (100110, 100130, 100140) but never the *success* alerts (100111, 100131, 100141). That difference is the point of the lab.

!!! note "Where the logs live"

    On a default Linux Docker install the volume is at `/var/lib/docker/volumes/vulnlab-logs/_data/`. Rootless Docker uses `~/.local/share/docker/volumes/`, so adjust the path in `ossec-localfile.xml`. The source IP is the Docker bridge gateway for requests from the host, so brute-force correlation is per source IP as Wazuh sees it.

## 4. Detect with Suricata

Suricata sees the HTTP traffic itself. It sees the **attempt** on both builds, but only the **responses** from the vulnerable build prove the attack worked (for example `uid=... gid=...` command output, or a raw `<script>` tag reflected back).

```bash
sudo cp lab/suricata/vulnlab.rules /var/lib/suricata/rules/vulnlab.rules
# add "vulnlab.rules" under rule-files: in /etc/suricata/suricata.yaml
sudo suricata -T -c /etc/suricata/suricata.yaml        # validate the config and rules
```

Traffic to `127.0.0.1` travels over the loopback interface, so sniff `lo` (or run the apps on a host-only lab network and sniff that interface). To test offline without any network, replay the included capture:

```bash
suricata -r lab/samples/lab-traffic.pcap -S lab/suricata/vulnlab.rules \
         -c /etc/suricata/suricata.yaml -k none -l /tmp/suri-out
cat /tmp/suri-out/fast.log
```

| SID | Detects |
|---|---|
| 4100001 / 4100002 | SQL injection pattern in a request body / URI |
| 4100010 | XSS pattern in the URI |
| 4100020 | Shell metacharacter in the `host` parameter |
| 4100030 | Many `/api/orders/<id>` requests from one source (IDOR enumeration) |
| 4100040 | Many `POST /login` requests from one source (brute force) |
| 4100050 | Command output (`uid=` ... `gid=`) in a response: **success evidence** |
| 4100060 | Raw `<script>` tag reflected in a response: **success evidence** |

## 5. Limits of these detections

- Pattern rules catch known payload shapes, not every variant. Encoding tricks and split payloads can evade them, which is why the correlation rules and the success-evidence rules matter.
- Web and network logs cannot prove XSS was reflected unless you inspect the response. The patched build also returns HTTP 200 for the XSS payload, so rule 100121 fires on both builds.
- These rules are written for this lab's log format. They are a learning exercise, not production detection content.

## How the rules are tested

- `scripts/run_attacks.py --check` proves the vulnerable build is exploitable and the patched build blocks each attack.
- `scripts/test_wazuh_rules.py --selftest` runs the Wazuh rules against real log lines using a small emulator of the rule features this file uses. It catches mistakes early but **is not Wazuh**, so confirm with `wazuh-logtest`.
- `scripts/test_suricata_rules.py` replays the packet capture through Suricata and checks which rules fire on which build.
- A GitHub Actions workflow (`lab-check.yml`) builds the containers and runs the attack and rule checks on every change.

## Read more

[SQL injection](labs/sqli.md) | [XSS](labs/xss.md) | [IDOR](labs/idor.md) | [Command injection](labs/command-injection.md) | [Tag index](tag-index.md)
