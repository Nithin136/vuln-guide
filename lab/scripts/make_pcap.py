#!/usr/bin/env python3
"""Build a replayable packet capture of lab traffic (needs: pip install scapy).

It sends real HTTP requests to the running lab containers, then writes the exact requests and responses into a
pcap, so you can test Suricata rules offline:
    python scripts/make_pcap.py samples/lab-traffic.pcap
    suricata -r samples/lab-traffic.pcap -S suricata/vulnlab.rules -c /etc/suricata/suricata.yaml -k none -l /tmp/suri-out
    cat /tmp/suri-out/fast.log
Only talks to 127.0.0.1 (the lab ports).
"""
import socket
import sys
import urllib.parse

from scapy.all import Ether, IP, TCP, wrpcap

HOST = "127.0.0.1"
CLIENT_IP, SERVER_IP = "10.0.2.15", "10.0.2.30"        # addresses written into the pcap (private lab range)


def exchange(port, raw):
    with socket.create_connection((HOST, port), timeout=8) as s:
        s.sendall(raw)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


def http(method, path, port, body=None, cookie=None):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {SERVER_IP}:{port}", "User-Agent: lab-client/1.0", "Connection: close"]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    data = b""
    if body is not None:
        data = body.encode()
        lines += ["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(data)}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + data


def cookie_of(resp):
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            return line.split(b":", 1)[1].split(b";")[0].strip().decode()
    return None


class Capture:
    def __init__(self):
        self.pkts, self.t, self.sport = [], 1_800_000_000.0, 40000

    def add(self, pkt):
        self.t += 0.02
        pkt.time = self.t
        self.pkts.append(pkt)

    def flow(self, port, req, resp):
        self.sport += 1
        eth_c = Ether(src="08:00:27:00:00:15", dst="08:00:27:00:00:30")
        eth_s = Ether(src="08:00:27:00:00:30", dst="08:00:27:00:00:15")
        c = lambda **kw: eth_c / IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=self.sport, dport=port, window=65535, **kw)
        s = lambda **kw: eth_s / IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=port, dport=self.sport, window=65535, **kw)
        cs, ss = 1000, 5000
        self.add(c(flags="S", seq=cs))
        self.add(s(flags="SA", seq=ss, ack=cs + 1))
        self.add(c(flags="A", seq=cs + 1, ack=ss + 1))
        self.add(c(flags="PA", seq=cs + 1, ack=ss + 1) / req)
        cs += 1 + len(req)
        self.add(s(flags="A", seq=ss + 1, ack=cs))
        ss += 1
        for i in range(0, len(resp), 1400):
            chunk = resp[i:i + 1400]
            self.add(s(flags="PA", seq=ss, ack=cs) / chunk)
            ss += len(chunk)
            self.add(c(flags="A", seq=cs, ack=ss))
        self.add(s(flags="FA", seq=ss, ack=cs))
        self.add(c(flags="FA", seq=cs, ack=ss + 1))
        self.add(s(flags="A", seq=ss + 1, ack=cs + 1))


def main(out):
    cap, log = Capture(), []

    def go(label, port, method, path, body=None, cookie=None):
        req = http(method, path, port, body, cookie)
        resp = exchange(port, req)
        cap.flow(port, req, resp)
        log.append((label, port))
        return resp

    q = urllib.parse.quote
    for port in (8081, 8082):
        cap.t += 120                                   # 2-minute gap so the threshold rules treat each build separately
        login = go("normal login", port, "POST", "/login", "username=priya&password=priya123")
        ck = cookie_of(login)
        go("normal own order", port, "GET", "/api/orders/1001", cookie=ck)
        go("normal lookup", port, "GET", "/tools/lookup?host=localhost")
        go("normal search", port, "GET", "/search?q=red+shoes")
        go("sqli comment", port, "POST", "/login", "username=" + q("admin' --", safe="") + "&password=x")
        go("sqli tautology", port, "POST", "/login", "username=admin&password=" + urllib.parse.quote_plus("' OR '1'='1"))
        go("xss script", port, "GET", "/search?q=" + q("<script>alert(1)</script>", safe=""))
        go("cmd injection", port, "GET", "/tools/lookup?host=" + q("localhost; id", safe=""))
        for oid in range(1000, 1011):
            go("idor scan", port, "GET", f"/api/orders/{oid}", cookie=ck)
        for i in range(8):
            go("brute force", port, "POST", "/login", f"username=admin&password=guess{i}")
    wrpcap(out, cap.pkts)
    print(f"wrote {out}: {len(cap.pkts)} packets, {len(log)} HTTP exchanges")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples/lab-traffic.pcap")
