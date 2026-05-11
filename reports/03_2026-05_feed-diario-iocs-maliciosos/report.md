# Feed Diário — IOCs Maliciosos 2026-05-11

**Author:** Higor Silva
**Date:** May/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

[Escreva aqui após gerar o PDF pelo TI Report Builder]

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Multiple sectors — social media users, streaming subscribers, crypto holders |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links via email/social media |
| **Associated Malware** | Emotet (C2 IPs) |
| **Threat Actor** | Multiple (Unknown) |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-05-11 |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Count | Classification |
|------|-------|----------------|
| IPs (C2) | — | — |
| URLs (Phishing) | — | — |
| **Total** | **—** | **— Malicious** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Credential Harvesting:** Phishing pages cloning major platforms to steal login credentials
- **C2 Communication:** Active C2 IPs identified via Feodo Tracker
- **Infrastructure Abuse:** Phishing pages hosted on legitimate platforms to evade domain reputation blocks

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure:**

| IP | Reputation | Source |
|----|-----------|--------|
| — | — | Feodo Tracker |

**Phishing Hosting Platforms Abused:**

| Platform | Count (approx.) |
|----------|----------------|
| — | — |

---

### 3.4 Tools Used in Analysis

| Category | Tool | Purpose |
|----------|------|---------|
| Feed Collection | Feed Aggregator (CTI Toolkit) | OpenPhish + Feodo Tracker ingestion |
| IOC Enrichment | VirusTotal, AbuseIPDB | Detection scoring and verdict |
| ATT&CK Mapping | ttp_mapper.py + manual review | TTP correlation |
| Report Generation | TI Report Builder | PDF output |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Procedure |
|--------|-----------|----|-----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Phishing URLs distributed via email/social media |
| Resource Development | Link Target | T1608.005 | Phishing infrastructure hosted on legitimate platforms |
| Resource Development | Domains | T1583.001 | Typosquatting domains mimicking major brands |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | Emotet C2 IPs communicating via HTTP/HTTPS |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS)
- Search SIEM/proxy logs for historical hits against listed indicators
- Alert SOC team for active monitoring

### Detection
- Monitor DNS queries for typosquatting patterns against major brand names
- Flag outbound connections to Cloudflare Workers and IPFS gateways for unusual patterns

### Hardening
- Enable browser-based phishing protection and enforce Safe Browsing policies
- Deploy MFA across all user accounts to mitigate credential harvesting impact

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
