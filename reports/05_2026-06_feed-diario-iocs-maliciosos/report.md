# Feed Diário — IOCs Maliciosos 2026-06-05

**Author:** Higor Silva
**Date:** June/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

On June 5, 2026, the automated CTI collection pipeline identified 305 indicators of compromise (IOCs) sourced from public threat intelligence feeds, of which 299 were classified as malicious after enrichment via VirusTotal and AbuseIPDB. The dataset includes 3 active Emotet C2 IP addresses identified via Feodo Tracker and 296 active phishing URLs sourced from OpenPhish. This collection cycle shows a significant shift in targeting compared to previous cycles: Banking, Finance, and Delivery impersonation emerged as the dominant phishing category (46 URLs), surpassing Social Media for the first time, followed by Gaming platforms — Roblox, Fortnite, and PUBG — which continued their upward trend (26 URLs). A notable infrastructure shift was also observed: GitHub Pages became the most abused legitimate hosting platform (30 URLs), overtaking Vercel (10 URLs) which had led in all previous cycles. Two Emotet C2 IPs (162[.]243[.]103[.]246 and 50[.]16[.]16[.]211) have appeared persistently across all collection cycles since May 4, indicating a stable, long-running C2 infrastructure. Immediate blocking of all listed indicators is recommended.

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Banking/finance users, gamers (Roblox, Fortnite, PUBG), social media, streaming, e-commerce |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links distributed via email and social media |
| **Associated Malware** | Emotet (C2 IPs via Feodo Tracker) |
| **Threat Actor** | Multiple (Unknown) |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-06-05 |
| **Feed Sources** | Feodo Tracker, OpenPhish |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Total | Malicious | Suspicious |
|------|-------|-----------|------------|
| IPs (C2) | 5 | 3 | 2 |
| URLs (Phishing) | 296 | 296 | 0 |
| **Total** | **305** | **299** | **2** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Banking & Delivery Impersonation:** Largest category this cycle (46 URLs) — phishing pages targeting bank portals, payment services, and parcel delivery (DPD, USPS, T-Mobile) represent a growing trend across cycles
- **Gaming Platform Targeting:** 26 URLs impersonating Roblox, Fortnite, and PUBG to steal accounts and in-game assets — consistent growth since May 11 (1 URL → 7 → 26)
- **C2 Infrastructure Persistence:** IPs 162[.]243[.]103[.]246 and 50[.]16[.]16[.]211 have been present in every collection since May 4 — indicating long-running, stable Emotet infrastructure
- **Infrastructure Platform Shift:** GitHub Pages overtook Vercel as the primary abuse platform (30 vs 10 URLs), suggesting actors are adapting to detection patterns
- **Credential Harvesting:** Phishing pages cloning Meta, Netflix, Amazon, and Microsoft services to steal login credentials

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure (Emotet — Feodo Tracker):**

| IP | Status | Persistence |
|----|--------|-------------|
| 162[.]243[.]103[.]246 | Malicious | Active since May 4 — all 5 cycles |
| 50[.]16[.]16[.]211 | Malicious | Active since May 4 — all 5 cycles |
| 27[.]133[.]154[.]218 | Malicious | Active since May 4 |
| 34[.]204[.]119[.]63 | Suspicious | Active since May 4 |
| 178[.]62[.]3[.]223 | Suspicious | Downgraded from Malicious |

**Phishing Hosting Platforms Abused:**

| Platform | URLs | Trend vs May 25 |
|----------|------|-----------------|
| GitHub Pages | 30 | ↑↑ Up from 4 — new leader |
| Vercel | 10 | ↓ Down from 25 |
| Blogspot | 4 | = Same |
| GitBook | 2 | ↓ Down from 6 |
| Weebly | 2 | ↓ Down from 4 |
| Framer | 1 | New |
| EdgeOne | 1 | ↓ Down from 4 |
| Wasmer | 1 | ↓ Down from 6 |
| Replit | 1 | New |
| Netlify | 1 | ↓ Down from 8 |
| Cloudflare | 1 | New |

**Phishing Target Categories:**

| Category | URLs | Trend vs May 25 |
|----------|------|-----------------|
| Others / Generic | 191 | = Similar |
| Banking / Finance / Delivery | 46 | ↑↑ Up from 4 — new #2 |
| Gaming (Roblox/Fortnite/PUBG) | 26 | ↑↑ Up from 7 — growing trend |
| Social Media (Meta) | 13 | ↑ Up from 11 |
| Streaming (Netflix) | 9 | ↑↑ Up from 2 |
| E-commerce (Amazon) | 5 | ↑ Up from 4 |
| Microsoft | 5 | ↑↑ Up from 0 |
| Crypto / Wallets | 1 | ↓ Down from 8 |

---

### 3.4 Tools Used in Analysis

| Category | Tool | Purpose |
|----------|------|---------|
| Feed Collection | feed_aggregator.py (CTI Toolkit) | OpenPhish + Feodo Tracker ingestion |
| IOC Enrichment | ioc_enricher.py — VirusTotal, AbuseIPDB | Detection scoring and verdict classification |
| ATT&CK Mapping | ttp_mapper.py + manual review | TTP correlation against MITRE ATT&CK v16 |
| Report Generation | TI Report Builder (HTML) | Structured PDF output |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Procedure |
|--------|-----------|----|-----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 296 active phishing URLs targeting banking/finance (46), gaming (26), social media (13), streaming (9), e-commerce (5), and Microsoft services (5) |
| Resource Development | Link Target | T1608.005 | Phishing infrastructure shifted to GitHub Pages (30 URLs) as primary abuse platform, followed by Vercel (10), Blogspot (4), and others — indicating platform-aware evasion behavior |
| Resource Development | Domains | T1583.001 | Lookalike domains impersonating banking institutions, gaming platforms, and parcel delivery services |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 3 persistent Emotet C2 IPs — 162[.]243[.]103[.]246 and 50[.]16[.]16[.]211 active across all 5 collection cycles since May 4, indicating stable long-running infrastructure |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS sinkhole)
- **Priority:** The 2 persistent Emotet C2 IPs present in all cycles should be blocked immediately if not already done
- Search SIEM and proxy logs for historical access to all listed indicators

### Detection
- Create detection rules for phishing pages hosted on GitHub Pages (github.io subdomains) — significant increase this cycle
- Monitor for banking and delivery impersonation patterns in proxy/DNS logs (DPD, USPS, T-Mobile lookalikes)
- Alert on connections to known Emotet C2 IPs — particularly the two persistent IPs active since May 4

### Threat Trending
- The consistent growth of Gaming-targeted phishing (1→7→26 URLs across cycles) warrants user awareness briefings for organizations with significant gaming demographics
- Banking/Finance/Delivery impersonation emerging as dominant vector — review email gateway rules accordingly

---

## 6. Appendix

### 6.1 Full IOC List
See [iocs.txt](./iocs.txt)

### 6.2 ATT&CK JSON
See [mitre_mapping.json](./mitre_mapping.json)

### 6.3 References
See [references.txt](./references.txt)

---

> **Disclaimer:** This report is based on open-source intelligence (OSINT). All IOCs are defanged. For educational and professional demonstration purposes only.
