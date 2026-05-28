# Feed Diário — IOCs Maliciosos 2026-05-25

**Author:** Higor Silva
**Date:** May/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

On May 25, 2026, the automated CTI collection pipeline identified 305 indicators of compromise (IOCs) sourced from public threat intelligence feeds, of which 234 were classified as malicious or suspicious after enrichment via VirusTotal and AbuseIPDB. The dataset comprises 4 active Emotet C2 IP addresses collected via Feodo Tracker, and 228 active phishing URLs sourced from OpenPhish. Compared to the previous collection cycle (May 11), this dataset shows a notable shift in targeting: gaming platforms (Roblox, Fortnite, PUBG) emerged as a prominent target alongside the persistent credential harvesting campaigns against social media (Meta/Facebook/Instagram), cryptocurrency wallets (Ledger, Trezor, MetaMask), and e-commerce platforms (Amazon, Shopee, eBay). A new pattern observed is the abuse of parcel delivery brand impersonation (DPD, USPS, T-Mobile) as phishing lures. Infrastructure-wise, IPFS saw increased abuse (10 URLs) relative to the previous cycle, while Vercel remains the most exploited legitimate hosting platform (25 URLs). Immediate blocking of all listed indicators at perimeter controls is recommended.

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Multiple — gaming users, social media, crypto holders, e-commerce shoppers, parcel delivery customers |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links distributed via email and social media |
| **Associated Malware** | Emotet (C2 IPs via Feodo Tracker) |
| **Threat Actor** | Multiple (Unknown) |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-05-25 |
| **Feed Sources** | Feodo Tracker, OpenPhish |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Total | Malicious | Suspicious |
|------|-------|-----------|------------|
| IPs (C2) | 5 | 4 | 1 |
| URLs (Phishing) | 234 | 228 | 6 |
| **Total** | **305** | **229** | **11** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Gaming Platform Impersonation:** Phishing pages targeting Roblox, Fortnite, and PUBG users to steal accounts and in-game assets — a notable increase compared to the previous cycle
- **Credential Harvesting:** Phishing pages cloning Meta, Instagram, Facebook, Amazon, Netflix, and banking portals
- **Crypto Asset Theft:** Typosquatting domains and pages impersonating Ledger, Trezor, MetaMask, and KuCoin targeting wallet credentials
- **Parcel Delivery Lures:** DPD and USPS impersonation pages used as phishing vectors — new pattern in this cycle
- **C2 Communication:** 4 active Emotet C2 IPs communicating via HTTP/HTTPS (same infrastructure as May 11 — persistent campaign)
- **IPFS Abuse:** Increased use of IPFS for hosting phishing content (10 URLs) — content hosted on decentralized storage complicates takedowns

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure (Emotet — Feodo Tracker):**

| IP | Status | Note |
|----|--------|------|
| 162[.]243[.]103[.]246 | Malicious | Persistent — also in May 11 collection |
| 50[.]16[.]16[.]211 | Malicious | Persistent — also in May 11 collection |
| 178[.]62[.]3[.]223 | Malicious | Persistent — also in May 11 collection |
| 27[.]133[.]154[.]218 | Malicious | Persistent — also in May 11 collection |
| 34[.]204[.]119[.]63 | Suspicious | Persistent — also in May 11 collection |

**Phishing Hosting Platforms Abused:**

| Platform | URLs | Trend vs May 11 |
|----------|------|-----------------|
| Vercel | 25 | ↓ Down from 76 |
| Blogspot | 18 | ↑ Up from 4 |
| IPFS | 10 | ↑ Up from 1 |
| Netlify | 8 | ↑ Up from 4 |
| Wasmer | 6 | ↑ New |
| GitBook | 6 | ↑ Up from 1 |
| Weebly | 4 | = Same |
| EdgeOne | 4 | ↑ Up from 1 |
| GitHub Pages | 4 | ↓ Down from 18 |
| GoDaddy | 1 | ↓ Down from 10 |
| Webflow | 1 | ↓ Down from 12 |

**Phishing Target Categories:**

| Category | URLs | Trend vs May 11 |
|----------|------|-----------------|
| Others / Generic | 192 | ↑ Up from 141 |
| Social Media (Meta) | 11 | ↓ Down from 26 |
| Crypto / Wallets | 8 | ↑ Up from 6 |
| Gaming (Roblox/Fortnite) | 7 | ↑ Up from 1 |
| Banking / Finance | 4 | = Same |
| E-commerce (Amazon/eBay) | 4 | ↓ Down from 19 |
| Streaming (Netflix) | 2 | ↓ Down from 18 |

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
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 228 active phishing URLs targeting gaming (Roblox, Fortnite, PUBG), crypto wallets (Ledger, Trezor, MetaMask), social media (Meta/Instagram), e-commerce (Amazon, Shopee), and parcel delivery services (DPD, USPS) |
| Resource Development | Link Target | T1608.005 | Phishing infrastructure hosted on Vercel (25), Blogspot (18), IPFS (10), Netlify (8), Wasmer (6), GitBook (6), and other legitimate platforms to evade reputation blocks |
| Resource Development | Domains | T1583.001 | Typosquatting domains impersonating Ledger (ledger-shop-now[.]com, ledger-entry[.]com), T-Mobile (t-mobile[.]fvypec[.]top), and DPD parcel delivery (dpd[.]czplqw[.]ink, dpd[.]shipdora[.]top) |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 4 persistent Emotet C2 IPs (same as May 11 collection) communicating over HTTP/HTTPS — indicates ongoing, stable C2 infrastructure |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS sinkhole)
- The 4 Emotet C2 IPs are persistent across two collection cycles — prioritize blocking if not already done
- Search SIEM and proxy logs for historical access to all listed indicators

### Detection
- Create alerts for connections to IPFS gateways (ipfs.dweb.link, ipfs.io) with unusual patterns — increased abuse observed
- Monitor DNS queries for typosquatting of parcel delivery brands (DPD, USPS, T-Mobile) — new lure pattern
- Flag outbound connections to Vercel, Netlify, GitBook, and Wasmer subdomains for review

### Hardening
- Enable browser phishing protection on all endpoints
- Deploy MFA to limit credential harvesting impact
- Brief users on parcel delivery phishing lures — a growing vector this cycle

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
