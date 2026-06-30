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

**C2 Infrastructure — Enriched (Feodo Tracker + ASN Data):**

| IP | Malware | Port | ASN | Provider | Country | First Seen | Status |
|----|---------|------|-----|----------|---------|------------|--------|
| 162[.]243[.]103[.]246 | Emotet (Heodo) | 8080 | AS14061 | DigitalOcean | US | 2022-06-04 | Offline |
| 50[.]16[.]16[.]211 | QakBot | 443 | AS14618 | Amazon AWS (EC2) | US | 2025-12-30 | Online |
| 27[.]133[.]154[.]218 | Emotet | 8080 | AS4766 | Korea Telecom | JP/KR | — | Active |
| 34[.]204[.]119[.]63 | QakBot | 443 | AS14618 | Amazon AWS (EC2) | US | — | Suspicious |
| 178[.]62[.]3[.]223 | Emotet | 7080 | AS14061 | DigitalOcean | NL | — | Suspicious |

**Infrastructure Analysis:**

The C2 infrastructure presents a mixed hosting profile. Two IPs (50[.]16[.]16[.]211 and 34[.]204[.]119[.]63) reside on Amazon AWS EC2 (AS14618), indicating actors leveraging legitimate cloud infrastructure for C2 hosting — a technique that complicates blocklist-based defenses since blocking entire AWS IP ranges would cause significant collateral damage. Two IPs (162[.]243[.]103[.]246 and 178[.]62[.]3[.]223) are hosted on DigitalOcean (AS14061), which has historically been abused for low-cost botnet hosting. The C2 ports used (443, 7080, 8080) blend with legitimate web traffic to evade port-based detection.

Notably, 162[.]243[.]103[.]246 was first identified by Feodo Tracker in June 2022 and remained in the active blocklist through March 2026 — nearly 4 years of continuous operation without successful takedown, suggesting either operator resilience or low enforcement priority. The Feodo Tracker FAQ confirms that datasets are currently empty following Operation Endgame (2024), which targeted Emotet and related families, yet these IPs persist in the blocklist, indicating residual infrastructure that survived the operation.

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

## 4. Diamond Model

The Diamond Model provides a structured framework to analyze the relationship between the adversary, capabilities, infrastructure, and victims observed in this collection cycle.

| Vertex | Observation |
|--------|-------------|
| **Adversary** | Multiple unattributed threat actors operating financially-motivated campaigns. The C2 infrastructure (Emotet/QakBot) and phishing campaigns show no overlap in TTPs suggesting independent operators sharing common tooling rather than a coordinated single actor. |
| **Capability** | Emotet loader (Heodo variant) communicating over HTTP/HTTPS on non-standard ports (7080, 8080). QakBot C2 on port 443 blending with HTTPS traffic. Phishing pages generated via clone tools or AI-assisted page builders, hosted on legitimate PaaS platforms to evade detection. |
| **Infrastructure** | C2: DigitalOcean VPS (AS14061) and Amazon AWS EC2 (AS14618). Phishing: Legitimate hosting platforms (GitHub Pages, Vercel, Blogspot, GoDaddy Sites) used as disposable infrastructure — rotated weekly to evade static blocklists. |
| **Victim** | End users globally across multiple sectors: banking/finance, e-commerce, gaming, social media, streaming. No specific geographic targeting identified — broad-spectrum campaigns maximizing reach. |

**Confidence Level Justification: Medium**

The Medium confidence rating reflects that while the C2 infrastructure attribution to Emotet and QakBot is confirmed by Feodo Tracker (a trusted, validated feed), the phishing campaign attribution to specific actors or groups remains unconfirmed. The targeting patterns and platform rotation behavior are consistent with multiple independent low-sophistication actors rather than a single coordinated threat group. Elevation to High confidence would require corroborating indicators from additional independent sources or direct malware analysis.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Procedure |
|--------|-----------|----|-----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 215 active phishing URLs across gaming (12), banking/delivery (9), e-commerce (8), crypto (5), streaming (5), social media (3), and Microsoft (1) |
| Resource Development | Link Target | T1608.005 | GitHub Pages (13), Vercel (11), Blogspot (10), GoDaddy (8), and IPFS (6) as primary abuse platforms — GoDaddy resurged significantly this cycle |
| Resource Development | Domains | T1583.001 | Lookalike domains impersonating banking institutions, gaming platforms, and delivery services |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 3 Emotet C2 IPs persistent for 6 consecutive weeks — no takedown observed; 162[.]243[.]103[.]246 and 50[.]16[.]16[.]211 present in every cycle since May 4 |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 6. Recommendations

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

## 7. Appendix

### 7.1 Full IOC List
See [iocs.txt](./iocs.txt)

### 7.2 ATT&CK JSON
See [mitre_mapping.json](./mitre_mapping.json)

### 7.3 References
See [references.txt](./references.txt)

---

> **Disclaimer:** This report is based on open-source intelligence (OSINT). All IOCs are defanged. For educational and professional demonstration purposes only.
