# Feed Diário — IOCs Maliciosos 2026-05-11

**Author:** Higor Silva
**Date:** May/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

On May 11, 2026, the automated CTI collection pipeline identified 305 indicators of compromise (IOCs) sourced from public threat intelligence feeds, of which 235 were classified as malicious or suspicious following enrichment via VirusTotal and AbuseIPDB. The dataset comprises 4 IP addresses associated with active Command and Control (C2) infrastructure of the Emotet malware family, identified via Feodo Tracker, and 225 active phishing URLs sourced from OpenPhish. Analysis of the phishing URLs reveals a multi-target campaign primarily impersonating social media platforms (Meta/Facebook/Instagram), e-commerce services (Amazon), streaming platforms (Netflix), and cryptocurrency wallets and exchanges. A defining characteristic of this campaign is the extensive abuse of legitimate hosting infrastructure — Vercel (76 URLs), GitHub Pages (18), Webflow (12), and GoDaddy Sites (10) — a technique used to evade domain reputation-based blocklists. Immediate blocking of all listed indicators at perimeter controls is recommended, along with a retrospective search of proxy and DNS logs for historical access.

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Multiple sectors — social media users, streaming subscribers, crypto holders, e-commerce customers |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links distributed via email and social media |
| **Associated Malware** | Emotet (C2 IPs via Feodo Tracker) |
| **Threat Actor** | Multiple (Unknown) |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-05-11 |
| **Feed Sources** | Feodo Tracker, OpenPhish |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Total | Malicious | Suspicious |
|------|-------|-----------|------------|
| IPs (C2) | 5 | 4 | 1 |
| URLs (Phishing) | 235 | 225 | 10 |
| **Total** | **305** | **229** | **11** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Credential Harvesting:** Phishing pages cloning major platforms (Meta, Amazon, Netflix, Microsoft, banking institutions) to steal user credentials
- **Crypto Asset Theft:** Pages impersonating Ledger, Trezor, MetaMask, and cryptocurrency exchanges targeting wallet seed phrases and private keys
- **C2 Communication:** 4 active Emotet C2 IP addresses communicating over HTTP/HTTPS, collected via Feodo Tracker blocklist
- **Infrastructure Abuse:** Threat actors hosting phishing pages on legitimate PaaS platforms to bypass domain reputation checks

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure (Emotet — Feodo Tracker):**

| IP | Status | Source |
|----|--------|--------|
| 162[.]243[.]103[.]246 | Malicious | Feodo Tracker |
| 50[.]16[.]16[.]211 | Malicious | Feodo Tracker |
| 178[.]62[.]3[.]223 | Malicious | Feodo Tracker |
| 27[.]133[.]154[.]218 | Malicious | Feodo Tracker |
| 34[.]204[.]119[.]63 | Suspicious | Feodo Tracker |

**Phishing Hosting Platforms Abused:**

| Platform | URLs Identified | Notes |
|----------|----------------|-------|
| Vercel | 76 | Most abused — free tier, instant deploy, no domain check |
| GitHub Pages | 18 | Repository-based hosting, trusted CDN |
| Webflow | 12 | No-code builder with free subdomains |
| GoDaddy Sites | 10 | Free website builder |
| Netlify | 4 | Similar to Vercel — free deploy pipeline |
| Blogspot | 4 | Google-hosted blogs |
| Weebly | 4 | Free website builder |
| Others (Zeabur, EdgeOne, GitBook, IPFS) | 6 | Emerging abuse targets |

**Phishing Target Categories:**

| Category | URLs | Examples Impersonated |
|----------|------|----------------------|
| Others / Generic | 141 | Gambling sites (Galabet), regional scams |
| Social Media (Meta) | 26 | Facebook, Instagram, Meta Business |
| E-commerce (Amazon) | 19 | Amazon clone pages |
| Streaming (Netflix) | 18 | Netflix clone pages |
| Banking / Finance | 8 | iCloud, bank portals, EasyBank |
| Microsoft | 6 | Microsoft support, Azure portals |
| Crypto / Wallets | 6 | Ledger, Trezor, MetaMask, NetCoins |
| Gaming (Roblox) | 1 | Roblox free items scam |

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
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 225 active phishing URLs distributed via email/social media, impersonating Netflix, Amazon, Meta, Microsoft, Ledger, and others |
| Resource Development | Link Target | T1608.005 | Phishing infrastructure hosted on Vercel (76), GitHub Pages (18), Webflow (12), GoDaddy (10), and other legitimate platforms to evade reputation blocks |
| Resource Development | Domains | T1583.001 | Typosquatting domains mimicking Meta (invoice-ads-manager[.]com), Microsoft (authorised-support[.]com), and cryptocurrency exchanges |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 4 active Emotet C2 IPs communicating over HTTP/HTTPS, identified via Feodo Tracker |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS sinkhole)
- Search SIEM and proxy logs for historical hits against all listed indicators
- Share indicators with SOC team for active monitoring and alerting

### Detection
- Monitor DNS queries for typosquatting patterns against major brand names (Meta, Amazon, Netflix, Microsoft)
- Flag and inspect outbound HTTP/HTTPS connections to Vercel, GitHub Pages, Webflow, and similar PaaS platforms for anomalous patterns
- Create SIEM rules for connections to the 4 Emotet C2 IPs

### Hardening
- Enable browser-based phishing protection (Google Safe Browsing, Microsoft SmartScreen) across all endpoints
- Deploy MFA on all user-facing services to reduce impact of credential harvesting
- Educate users on phishing indicators — legitimate services do not request credentials via unsolicited links

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
