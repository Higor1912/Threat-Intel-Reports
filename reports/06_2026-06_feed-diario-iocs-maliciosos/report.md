# Feed Diário — IOCs Maliciosos 2026-06-08

**Author:** Higor Silva
**Date:** June/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

On June 8, 2026, the automated CTI collection pipeline identified 305 indicators of compromise (IOCs) from public threat intelligence feeds, of which 235 were classified as malicious or suspicious after enrichment via VirusTotal and AbuseIPDB. The dataset includes 3 active Emotet C2 IPs from Feodo Tracker and 215 active phishing URLs from OpenPhish. The most significant finding in this cycle is the persistence of the Emotet C2 infrastructure: IPs 162[.]243[.]103[.]246, 50[.]16[.]16[.]211, and 27[.]133[.]154[.]218 have been present in every collection since May 4 — now spanning 6 consecutive weeks with no signs of takedown, indicating a stable, well-maintained botnet. On the phishing side, the targeting mix became more diversified compared to the previous cycle, with e-commerce (Amazon, 8 URLs) and crypto wallets (5 URLs) increasing their share while gaming and banking/delivery decreased. GoDaddy Sites re-emerged as a significant hosting platform (8 URLs) after a near-absence in the June 5 cycle. Immediate blocking of all listed indicators is recommended, with special priority given to the 3 persistent Emotet C2 IPs.

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Gaming users, banking/finance, e-commerce, crypto, streaming, social media |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links distributed via email and social media |
| **Associated Malware** | Emotet (C2 IPs via Feodo Tracker) |
| **Threat Actor** | Multiple (Unknown) |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-06-08 |
| **Feed Sources** | Feodo Tracker, OpenPhish |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Total | Malicious | Suspicious |
|------|-------|-----------|------------|
| IPs (C2) | 5 | 3 | 2 |
| URLs (Phishing) | 232 | 215 | 17 |
| **Total** | **305** | **218** | **19** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Persistent Emotet C2:** The 3 core Emotet C2 IPs have been active across all 6 collection cycles since May 4 with no interruption — a notable indicator of infrastructure resilience and lack of law enforcement action
- **Diversified Phishing Mix:** Targeting spread across 7 categories this cycle — no single dominant vector, suggesting broad-spectrum phishing campaigns from multiple unrelated actors
- **GoDaddy Resurgence:** GoDaddy Sites returned as a significant hosting platform (8 URLs) after near-absence in cycle 5, suggesting rotational platform abuse to avoid detection
- **E-commerce Increase:** Amazon-targeting URLs rose to 8 (from 4 in cycle 5), approaching the levels seen in earlier cycles
- **Suspicious URL Spike:** 17 suspicious URLs (vs 0 in cycle 5) — higher uncertainty in classification may reflect new infrastructure not yet flagged by enrichment sources

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure (Emotet — Feodo Tracker):**

| IP | Status | Persistence |
|----|--------|-------------|
| 162[.]243[.]103[.]246 | Malicious | **6 consecutive cycles** — since May 4 |
| 50[.]16[.]16[.]211 | Malicious | **6 consecutive cycles** — since May 4 |
| 27[.]133[.]154[.]218 | Malicious | **6 consecutive cycles** — since May 4 |
| 34[.]204[.]119[.]63 | Suspicious | Active since May 4 |
| 178[.]62[.]3[.]223 | Suspicious | Active since May 4 |

**Phishing Hosting Platforms Abused:**

| Platform | URLs | Trend vs Jun 5 |
|----------|------|----------------|
| GitHub Pages | 13 | ↓ Down from 30 |
| Vercel | 11 | ↑ Up from 10 |
| Blogspot | 10 | ↑ Up from 4 |
| GoDaddy | 8 | ↑↑ Up from 1 — resurgence |
| IPFS | 6 | = Same |
| Wasmer | 5 | ↑ Up from 1 |
| Netlify | 2 | ↓ Down from 1 |
| EdgeOne | 2 | ↑ Up from 1 |
| Replit | 1 | = Same |

**Phishing Target Categories:**

| Category | URLs | Trend vs Jun 5 |
|----------|------|----------------|
| Others / Generic | 172 | ↓ Down from 191 |
| Gaming | 12 | ↓ Down from 26 |
| Banking / Finance / Delivery | 9 | ↓ Down from 46 |
| E-commerce (Amazon) | 8 | ↑ Up from 5 |
| Crypto / Wallets | 5 | ↑ Up from 1 |
| Streaming (Netflix) | 5 | ↑ Up from 9 |
| Social Media (Meta) | 3 | ↓ Down from 13 |
| Microsoft | 1 | ↓ Down from 5 |

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
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 215 active phishing URLs across gaming (12), banking/delivery (9), e-commerce (8), crypto (5), streaming (5), social media (3), and Microsoft (1) |
| Resource Development | Link Target | T1608.005 | GitHub Pages (13), Vercel (11), Blogspot (10), GoDaddy (8), and IPFS (6) as primary abuse platforms — GoDaddy resurged significantly this cycle |
| Resource Development | Domains | T1583.001 | Lookalike domains impersonating banking institutions, gaming platforms, and delivery services |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 3 Emotet C2 IPs persistent for 6 consecutive weeks — no takedown observed; 162[.]243[.]103[.]246 and 50[.]16[.]16[.]211 present in every cycle since May 4 |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS sinkhole)
- **Priority:** 3 Emotet C2 IPs active for 6 consecutive weeks — if not already blocked, escalate immediately
- Search SIEM logs for any historical communication with the 3 persistent C2 IPs

### Detection
- Flag outbound connections to GoDaddy Sites subdomains (godaddysites.com) showing unusual patterns — significant increase this cycle
- Monitor for IPFS gateway abuse (ipfs.dweb.link, ipfs.io) as a persistent phishing delivery vector
- Maintain blocking of GitHub Pages (github.io) subdomains used for phishing — consistent presence across all cycles

### Threat Trending (6-cycle summary)
- The 3 core Emotet C2 IPs have been stable for 6 weeks — this infrastructure longevity is notable and warrants escalation to threat intelligence sharing platforms
- Gaming phishing peaked at cycle 5 (26 URLs) and is declining — may indicate campaign rotation
- Platform abuse rotates week-to-week (Vercel → GitHub → GoDaddy) — static blocklists are insufficient; behavior-based detection is recommended

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
