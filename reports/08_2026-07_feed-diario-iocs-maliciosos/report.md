# Feed Diário — IOCs Maliciosos 2026-07-06

**Author:** Higor Silva
**Date:** July/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

On July 06, 2026, the automated CTI collection pipeline identified 305 indicators of compromise (IOCs) from public threat intelligence feeds, of which 278 were classified as malicious or suspicious after enrichment via VirusTotal and AbuseIPDB. The dataset includes 2 active C2 IP addresses identified via Feodo Tracker and 241 active phishing URLs from OpenPhish. Dominant phishing targets this cycle: Gaming (17), Social Media (Meta) (8). A defining characteristic is the abuse of legitimate hosting platforms — GitHub Pages (14), Blogspot (7), Vercel (5) — to evade domain reputation-based blocklists. Immediate blocking of all listed indicators at perimeter controls is recommended.

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Multiple sectors — Gaming, Social Media (Meta), Banking / Finance / Delivery |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links distributed via email and social media |
| **Associated Malware** | Emotet (C2 IPs via Feodo Tracker) |
| **Threat Actor** | Multiple (Unknown) |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-07-06 |
| **Feed Sources** | Feodo Tracker, OpenPhish |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Total | Malicious | Suspicious |
|------|-------|-----------|------------|
| IPs (C2) | 5 | 2 | 3 |
| URLs (Phishing) | 273 | 241 | 32 |
| **Total** | **305** | **243** | **35** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Persistent C2 Infrastructure:** 2 Emotet C2 IPs active in this collection cycle — communicating over HTTP/HTTPS on non-standard ports to blend with legitimate traffic
- **Credential Harvesting — Social Media:** 8 URLs impersonating Meta/Facebook/Instagram to steal login credentials
- **Credential Harvesting — E-commerce:** 4 URLs cloning Amazon checkout/login pages
- **Crypto Asset Theft:** 3 URLs impersonating Ledger, Trezor, MetaMask targeting wallet credentials and seed phrases
- **Gaming Platform Targeting:** 17 URLs impersonating Roblox, Fortnite, or PUBG to steal accounts and in-game assets
- **Banking & Delivery Impersonation:** 6 URLs targeting bank portals, payment services, and parcel delivery (DPD, USPS, T-Mobile)
- **Streaming Impersonation:** 2 Netflix clone pages designed to harvest payment credentials
- **Infrastructure Abuse:** Phishing pages hosted on legitimate PaaS platforms (GitHub Pages, Blogspot, Vercel) to evade reputation-based blocking

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure — Enriched (Feodo Tracker + ASN Data):**

| IP | Malware | Port | ASN | Provider | Country | First Seen | Status |
|----|---------|------|-----|----------|---------|------------|--------|
| 162[.]243[.]103[.]246 | Emotet (Heodo) | 8080 | AS14061 | DigitalOcean | US | 2022-06-04 | Offline |
| 27[.]133[.]154[.]218 | Emotet | 8080 | AS4766 | Korea Telecom | JP/KR | — | Active |
| 50[.]16[.]16[.]211 | QakBot | 443 | AS14618 | Amazon AWS (EC2) | US | 2025-12-30 | Online |
| 34[.]204[.]119[.]63 | QakBot | 443 | AS14618 | Amazon AWS (EC2) | US | — | Suspicious |
| 178[.]62[.]3[.]223 | Emotet | 7080 | AS14061 | DigitalOcean | NL | — | Suspicious |

**Infrastructure Analysis:**

The C2 infrastructure presents a mixed hosting profile across multiple cloud providers. The C2 ports used (443, 7080, 8080) are chosen to blend with legitimate HTTP/HTTPS traffic, complicating port-based detection. Actors leveraging AWS EC2 (AS14618) benefit from implicit protection since many organizations whitelist AWS IP ranges, making blocklist-only defenses insufficient.

**Phishing Hosting Platforms Abused:**

| Platform | URLs |
|----------|------|
| GitHub Pages | 14 |
| Blogspot | 7 |
| Vercel | 5 |
| Framer | 4 |
| Weebly | 4 |
| Netlify | 3 |
| Replit | 2 |
| Wasmer | 2 |
| Webflow | 2 |

**Phishing Target Categories:**

| Category | URLs |
|----------|------|
| Others | 200 |
| Gaming | 17 |
| Social Media (Meta) | 8 |
| Banking / Finance / Delivery | 6 |
| E-commerce (Amazon) | 4 |
| Crypto / Wallets | 3 |
| Streaming (Netflix) | 2 |
| Microsoft | 1 |

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
| **Adversary** | Multiple unattributed threat actors operating financially-motivated campaigns. C2 operators (Emotet) and phishing actors appear to be independent groups sharing no direct coordination. |
| **Capability** | Emotet loaders communicating over HTTP/HTTPS on ports 443/7080/8080. Phishing pages generated via clone tools hosted on legitimate PaaS platforms to evade domain reputation controls. |
| **Infrastructure** | C2: Multiple cloud providers (DigitalOcean AS14061, Amazon AWS AS14618). Phishing: GitHub Pages, Blogspot, Vercel used as disposable infrastructure — rotated to evade static blocklists. |
| **Victim** | End users globally across multiple sectors: gaming, social media (meta), banking / finance / delivery. Broad-spectrum targeting with no identified geographic restriction. |

**Confidence Level Justification: Medium**

The Medium confidence rating reflects that C2 attribution to Emotet is confirmed by Feodo Tracker (a trusted, validated feed), while phishing actor attribution remains unconfirmed. The targeting patterns are consistent with multiple independent low-sophistication actors. Elevation to High confidence would require corroborating indicators from additional independent sources or direct malware analysis.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Procedure |
|--------|-----------|----|-----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 241 active phishing URLs targeting gaming, social media (meta) |
| Resource Development | Link Target | T1608.005 | Phishing infrastructure hosted on GitHub Pages (14), Blogspot (7), Vercel (5) to evade reputation blocks |
| Resource Development | Domains | T1583.001 | Lookalike and typosquatting domains impersonating major brands used as phishing landing pages |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 2 active Emotet C2 IPs identified via Feodo Tracker, communicating over HTTP/HTTPS |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 6. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS sinkhole)
- Search SIEM and proxy logs for historical access to all listed indicators
- Alert SOC team for active monitoring of listed C2 IPs

### Detection
- Flag outbound HTTP/HTTPS connections to GitHub Pages, Blogspot, Vercel subdomains for unusual patterns
- Monitor DNS queries for typosquatting of major brand names
- Create detection rules for C2 communication on ports 443/7080/8080 to the listed IPs

### Hardening
- Enable browser-based phishing protection on all endpoints (Google Safe Browsing, Microsoft SmartScreen)
- Deploy MFA on all user-facing services to reduce credential harvesting impact
- Educate users on phishing indicators — legitimate services do not request credentials via unsolicited links

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
