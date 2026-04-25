# Network Scanner — Diagnosis & Improvement Plan

**Status:** Producing thin / inaccurate results that don't surface real vulnerabilities.
**Owner:** Pratik
**Last reviewed:** 2026-04-26

---

## TL;DR

The current network scanner (`app/scanners/network_scanner/network_scanner.py`) is a **64-line TCP port checker against 10 hardcoded ports**. It cannot find vulnerabilities on an IP — it just lists which of {21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379} are open. To produce useful findings we need: full port coverage, service / version detection, banner grabbing, TLS / protocol inspection, and CVE lookup.

This document maps the gap and proposes a phased fix.

---

## 1. What the scanner does today

`tcp_connect_scan(target_ip)`:

```python
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis"}

for port, service in COMMON_PORTS.items():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    if sock.connect_ex((target_ip, port)) == 0:
        scan_result["open_ports"].append({"port": port, "service": service})
```

Output:
```json
{
  "scan_type": "network",
  "target": "203.0.113.10",
  "open_ports": [{"port": 22, "service": "SSH"}, {"port": 443, "service": "HTTPS"}],
  "scan_time": "2026-04-26T12:00:00"
}
```

Storage (`app/api/scans.py:478`): only the target IP is persisted to `ScanResult` — the open-ports list is **not stored as Vulnerability records**, so the scan doesn't show up in dashboards / severity counts the way subdomain & API scans do.

---

## 2. Why results are poor

| # | Problem | Impact |
|---|---------|--------|
| 1 | **Only 10 ports scanned** | Misses RDP (3389), SMB (445), MongoDB (27017), Elasticsearch (9200), Memcached (11211), Docker API (2375/2376), Kubernetes API (6443/8443/10250), application ports (3000/5000/8000/8080/8888), DNS-over-TLS (853), LDAP (389/636), etc. |
| 2 | **No service / version detection** | "Port 22 open" tells you nothing. You need `OpenSSH 8.2p1` to map to CVE-2020-15778. Without versions, no CVE matching is possible. |
| 3 | **No banner grabbing** | Won't catch info disclosure (Server: nginx/1.14.0 → known CVEs), default credentials banners, debug versions. |
| 4 | **No TLS inspection** | Can't flag expired certs, weak ciphers (RC4, 3DES), SSLv3/TLSv1.0/1.1, weak key exchange, Heartbleed, ROBOT, missing OCSP, hostname mismatch. |
| 5 | **No protocol probes** | SSH algorithms / kex weaknesses, FTP anonymous login, SMTP open relay, SNMP default community strings, DNS recursion / zone transfer — all undetected. |
| 6 | **No CVE lookup** | Even with versions, there's no NVD / OSV / vulners integration. Findings have no severity, no CVSS, no remediation. |
| 7 | **No UDP scanning** | DNS, SNMP, NTP, IPMI, NetBIOS, IPsec — all UDP. Currently invisible. |
| 8 | **Synchronous + 1 s timeout** | Serial socket calls. 1 s timeout drops slow links. 10 ports × 1 s = 10 s ceiling, but real production ranges (1-65535) at this rate would take 18 hours. |
| 9 | **No findings produced** | The `Vulnerability` table is never written. Ports list isn't displayed as severity-rated findings in the UI. The scan produces output the rest of the platform doesn't know how to render. |
| 10 | **No host discovery** | Single IP only. Can't scan a CIDR range or take an asset group. |
| 11 | **No rate limiting / IDS evasion** | Will trip target firewalls and get blacklisted on the first scan against a real network. |
| 12 | **No IPv6** | `socket.AF_INET` is hardcoded. |

---

## 3. What "proper" network scanning looks like

Compare to industry tools (Nessus, Qualys VMDR, OpenVAS, Rapid7 InsightVM):

| Capability | Today | Target |
|------------|-------|--------|
| Port range | 10 fixed | Top-1000 default + configurable full 1-65535 |
| Protocol | TCP only | TCP + UDP + ICMP |
| Service ID | Hardcoded port→name map | Probe-based (banner, response signatures) |
| Version detection | None | nmap `-sV` style probes |
| TLS audit | None | Full TLS scan: cert, ciphers, protocols, vulnerabilities |
| OS fingerprint | None | nmap `-O` (TTL + window size + TCP options) |
| CVE matching | None | NVD / OSV / vulners.com lookup keyed by `cpe:` strings |
| Findings model | List of ports | Vulnerability records w/ severity, CVSS, remediation |
| Concurrency | Sequential | 100s of parallel probes (asyncio or thread pool) |
| Auth-aware | No | Optional credentialed scan (SSH login → patch level audit) |
| Stealth | No | Configurable timing templates (T0-T5), packet fragmentation |

We don't need all of this for v1. We need the **minimum that produces real findings**.

---

## 4. Phased improvement plan

### Phase N1 — Port coverage + service detection (highest ROI, ~1 day)

**Goal:** Replace the 10-port socket scan with `nmap -sV` against top-1000 ports.

**Why first:** Service / version detection is the foundation of every other check. Without it, no CVE lookup is possible.

**Implementation:**
- Switch `network_scanner.py` to `python-nmap` (subprocess wrapper around the `nmap` binary).
- Run `nmap -sV --top-ports 1000 -T4 <ip>`.
- Parse XML output → list of `(port, protocol, service, product, version, cpe)` tuples.
- Add `nmap` to the Docker image (`apt-get install -y nmap`).

**Acceptance:** Scanning a known target produces output like:
```
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu
80/tcp   open  http       nginx 1.14.0
443/tcp  open  ssl/http   nginx 1.14.0
3306/tcp open  mysql      MySQL 5.7.30
```

---

### Phase N2 — CVE lookup (high ROI, ~1 day)

**Goal:** Map `(product, version)` to known CVEs and emit Vulnerability records.

**Implementation:**
- Use `cpe:` strings from nmap output to query NVD or vulners.com.
- For each match, create a `Vulnerability` row with:
  - `severity` (from CVSS score)
  - `cvss_score`, `cvss_vector`
  - `description` (CVE summary)
  - `recommendation` (NVD reference link)
- De-dupe by CVE ID per host.

**Library options:**
- `cve-lookup` (offline NVD JSON feed) — no network calls, ~500 MB index, fast.
- `vulners` (online API) — small payload, requires API key, rate-limited.
- Recommendation: vulners for v1, cve-lookup for v2 (offline mode for air-gapped customers).

**Acceptance:** Scanning a target with `OpenSSH 8.2p1` surfaces CVE-2020-15778 and CVE-2021-41617 as findings in the platform UI with HIGH/MEDIUM severity.

---

### Phase N3 — TLS inspection (~half day)

**Goal:** For every TLS-bearing port (443, 8443, 993, 995, 465, …), audit the TLS posture.

**Implementation:**
- Use `sslyze` (Python library, well-maintained, returns structured dataclasses).
- Check: protocol versions, cipher suites, certificate expiry, hostname mismatch, weak DH, Heartbleed, ROBOT, CCS injection, OCSP stapling.
- Emit one finding per weakness.

**Acceptance:** Scanning a server with TLSv1.0 enabled produces a "Weak TLS Protocol Version" finding.

---

### Phase N4 — Findings model parity (~half day)

**Goal:** Network scan results show up in the platform UI like API and subdomain findings.

**Implementation:**
- Update `app/api/scans.py:478` block to:
  1. Persist open ports as `IPAddress` rows (or extend ScanResult).
  2. For each CVE / TLS / protocol finding, create a `Vulnerability` row linked to the IP.
  3. Update `Scan.findings_count` and severity counts.
- Update `frontend-react/src/pages/Scan.jsx` network detail view to render the same finding cards used elsewhere (severity badge, CVSS, vector, description, remediation).

**Acceptance:** Network scan against an IP shows up in `/scan/<id>` with the same UI affordances as an API scan.

---

### Phase N5 — Polish (later)

- UDP scan support (`nmap -sU --top-ports 100`).
- IPv6 (`nmap -6`).
- CIDR range support (`192.0.2.0/24`).
- Auth-aware scans (SSH credentials → `lynis` / patch audit).
- Configurable timing templates.
- IDS evasion options.
- Scheduled re-scans (already have `ScheduledScan` infra).

---

## 5. Library and tooling decisions

| Capability | Library | Why |
|-----------|---------|-----|
| Port + service + version scan | `python-nmap` (wraps `nmap` binary) | De-facto standard. Battle-tested fingerprinting. Don't reinvent. |
| TLS audit | `sslyze` | Structured output, modern, maintained. Better than parsing `openssl s_client`. |
| CVE lookup | `vulners` API (v1) → offline NVD feed (v2) | Vulners is fast to integrate. Offline feed for customers who require air-gap. |
| Async port scan (no nmap) | `asyncio` + `aiohttp` for HTTP probes | Only if we want to avoid the nmap binary dependency. Slower to build. |

**Docker image impact:** Adding `nmap` adds ~30 MB to the image. Acceptable. `sslyze` is pip-installable. Vulners SDK is small.

---

## 6. Open questions

1. **Targeting:** Should network scans accept hostnames (resolve to IP first) or only IPs? Today it's IPs only. Hostnames would integrate better with the asset model.
2. **Authorization:** Do we restrict network scans to IPs the tenant owns (asset inventory check), or trust the user? Other tools require RoE attestation — we should too, to avoid being weaponized.
3. **Concurrency budget:** Should one scan use up to N parallel nmap processes, or queue? Affects how big a CIDR range we can handle.
4. **Findings dedup across scans:** When the same IP is scanned twice, do we close stale findings or always append? (Subdomain scanner has this same question — solve once.)
5. **Compliance:** Some jurisdictions / providers (AWS, GCP, Azure) require pre-authorization for port scans of their IP ranges. Add a pre-flight check that warns when the target is in a known cloud range without authorization.

---

## 7. Acceptance bar for "proper results"

A network scan against a public test target with known issues (e.g. `scanme.nmap.org`) should produce:

- ≥ 1 finding per outdated software version (CVE-mapped, severity-rated)
- ≥ 1 finding per weak TLS configuration (if applicable)
- ≥ 1 informational finding for service banners
- Output renders in the platform UI with the same fidelity as API scan results
- Total scan time for a single host: < 2 minutes (with `-T4` timing template)

If a scan produces zero findings and the target has known issues, that's the regression test that fails.

---

## 8. Non-goals

- Active exploitation (don't be Metasploit — we're a vulnerability scanner, not an attack framework).
- Zero-day discovery.
- Web app testing (that's what the API & subdomain scanners are for).
- IDS / firewall evasion as a default behavior.
