# Threat Intelligence Report — [TITLE]

**Author:** Higor Silva
**Date:** [MONTH/YEAR]
**TLP:** [WHITE / GREEN / AMBER / RED]
**Version:** 1.0

---

## 1. Executive Summary

[2–3 paragraphs. Answer: what was observed, who is the actor, what is the potential impact, what immediate action is recommended. Write for a non-technical audience.]

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | [Phishing / Ransomware / APT / Malware / etc.] |
| **Target** | [Sector / Region / Organization type] |
| **Motivation** | [Financial / Espionage / Hacktivism / Sabotage] |
| **Attack Vector** | [Email / Exploit / Supply Chain / etc.] |
| **Associated Malware** | [Name or N/A] |
| **Threat Actor** | [Name or Unknown] |
| **Confidence Level** | [High / Medium / Low] |
| **First Seen** | [YYYY-MM-DD] |
| **Last Seen** | [YYYY-MM-DD] |

[Description of the campaign, context, and observed activity.]

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | `[defanged]` | [C2 / Scanner / etc.] |
| Domain | `[defanged]` | [Phishing / C2 / etc.] |
| URL | `[defanged]` | [Payload / Landing page] |
| Hash (SHA256) | `[hash]` | [File description] |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- [Bullet point of each observed behavior — execution, persistence, C2, etc.]

---

### 3.3 Infrastructure Analysis

[Describe C2 infrastructure, hosting providers, ASNs, passive DNS pivots, certificate patterns, etc.]

---

### 3.4 Tools Used in Analysis

| Category | Tool | Purpose |
|----------|------|---------|
| IOC Enrichment | VirusTotal, AbuseIPDB | Detection scoring and metadata |
| OSINT | Shodan, Whois, Passive DNS | Infrastructure pivoting |
| Sandbox | Any.Run, Hybrid Analysis | Dynamic behavior analysis |
| ATT&CK Mapping | ttp_mapper.py, attack.mitre.org | TTP correlation |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Procedure |
|--------|-----------|----|-----------|
| [Tactic] | [Technique name] | [T1xxx.xxx] | [What the actor did] |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Impact Assessment

- **Financial impact:** [Description or N/A]
- **Operational impact:** [Description or N/A]
- **Reputational impact:** [Description or N/A]
- **Data exposure:** [Description or N/A]

---

## 6. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at the perimeter controls.
- Search SIEM logs for historical hits against listed indicators.
- [Campaign-specific recommendations]

### For Organizations
- [Detection rule recommendations — SIEM, EDR, firewall]
- [Hardening recommendations based on TTPs observed]

### For End Users
- [If applicable]

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
