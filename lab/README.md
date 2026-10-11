# VulnLab (local lab)

An **intentionally vulnerable** Flask app and a **patched** build of the same app, with Wazuh and Suricata detection rules.

**Local use only.** Run it on a lab machine or VM you control. Never expose the ports or run it on a shared or production host.

```bash
cd lab
docker compose up --build -d             # vulnerable: 127.0.0.1:8081, patched: 127.0.0.1:8082
python3 scripts/run_attacks.py --check   # attack both builds
python3 scripts/run_attacks.py --noisy   # also brute force + ID enumeration (for the correlation rules)
docker compose down -v
```

| Path | Purpose |
|---|---|
| `app/` | The Flask app, Dockerfile and pinned requirements |
| `docker-compose.yml` | Two hardened containers bound to 127.0.0.1, plus a log volume `vulnlab-logs` |
| `scripts/run_attacks.py` | Attacks both builds and prints a pass/fail table |
| `scripts/test_wazuh_rules.py` | Offline check of the Wazuh rules against real logs (an emulator; confirm with `wazuh-logtest`) |
| `scripts/test_suricata_rules.py` | Replays `samples/lab-traffic.pcap` through Suricata and checks which rules fire |
| `scripts/make_pcap.py` | Rebuilds the pcap from the running lab (needs `pip install scapy`) |
| `wazuh/` | `vulnlab_rules.xml` (13 rules) and the `ossec.conf` snippet that ships the logs |
| `suricata/` | `vulnlab.rules` (8 rules) |
| `samples/` | Real log lines from both builds and the pcap |

Full walkthrough: `docs/local-lab.md` (also on the site under **Local lab**).
