# Threat Intelligence Reports

Operational threat intelligence reports based on OSINT investigation and MITRE ATT&CK mapping. Each report documents a real-world threat campaign — covering adversary infrastructure, IOC correlation, TTP analysis, and actionable detection recommendations.

---

## Reports

| # | Date | Title | Type | Threat Actor |
|---|------|-------|------|--------------|
| 01 | Oct/2025 | [Efimer Trojan — AI-Assisted Phishing Campaign Targeting Brazilian Users](./2025-10_EfimerTrojan-Phishing/report.md) | Phishing / Malware | Unknown (FIN) |

> New reports are published monthly. Each analysis follows the methodology described below.

---

## Methodology

All reports follow a structured intelligence process:

**Collection** → OSINT sources (VirusTotal, OTX, ThreatFox, Shodan, passive DNS, cert transparency)  
**Processing** → IOC extraction, defanging, deduplication  
**Analysis** → Behavioral mapping, infrastructure pivoting, TTP correlation  
**Production** → Structured report with MITRE ATT&CK mapping and detection recommendations  
**Dissemination** → Published in this repository with full artifact set

---

## Report Structure

Each report is organized in its own folder:

```
YYYY-MM_[ThreatName]/
├── report.md           # Full technical analysis
├── iocs.txt            # Defanged indicators of compromise
├── mitre_mapping.json  # ATT&CK techniques in structured format
├── references.txt      # Sources and external references
└── screenshots/        # Visual evidence from analysis
```

---

## MITRE ATT&CK Coverage

Techniques documented across all reports:

| Technique ID | Name | Reports |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | 01 |
| T1204 | User Execution | 01 |
| T1027 | Obfuscated Files or Information | 01 |
| T1003 | OS Credential Dumping | 01 |
| T1041 | Exfiltration Over C2 Channel | 01 |
| T1547.001 | Registry Run Keys / Startup Folder | 01 |

---

## Tools Used

| Category | Tools |
|---|---|
| IOC Lookup & Enrichment | VirusTotal, AlienVault OTX, ThreatFox |
| Sandbox Analysis | Any.Run, Hybrid Analysis |
| Infrastructure / OSINT | Shodan, Whois, Wayback Machine, Passive DNS |
| ATT&CK Mapping | attack.mitre.org, MITRE Navigator |
| Reporting | Markdown, structured JSON |

---

## About

This repository is part of my public CTI portfolio. All analyses are based on open-source intelligence (OSINT) and are published for educational and professional demonstration purposes.

**Author:** Higor Silva  
**Focus:** Operational Threat Intelligence · Adversary Tracking · Infrastructure Analysis  
**Contact:** [LinkedIn](https://www.linkedin.com/in/higor-silva-sec)

---

> IOCs are defanged throughout all reports. Do not use them in production environments without proper validation.
