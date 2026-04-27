# Threat Intelligence Reports

Operational threat intelligence reports based on OSINT investigation and MITRE ATT&CK mapping. Each report documents a real-world threat campaign — covering adversary infrastructure, IOC correlation, TTP analysis, and actionable detection recommendations.

![Reports](https://img.shields.io/badge/Reports-01-blue)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v16-red)
![TLP](https://img.shields.io/badge/TLP-GREEN%20%7C%20AMBER-orange)
![Tooling](https://img.shields.io/badge/Tooling-CTI%20Toolkit-informational)

---

## Reports

| # | Date | Title | Type | Threat Actor | Key TTPs | PDF |
|---|------|-------|------|--------------|----------|-----|
| 01 | Oct/2025 | [Efimer Trojan — AI-Assisted Phishing Campaign Targeting Brazilian Users](./reports/01_2025-10_efimer-trojan-phishing-brazil/report.md) | Phishing / Malware | Unknown (FIN) | T1566.002, T1027, T1003 | [↓ PDF](./reports/01_2025-10_efimer-trojan-phishing-brazil/report.pdf) |

> New reports are published monthly. Each analysis follows the methodology described below.

---

## Methodology

All reports follow a structured intelligence cycle:

```
Collection → Processing → Analysis → Production → Dissemination
```

| Phase | Description |
|-------|-------------|
| **Collection** | OSINT sources — VirusTotal, AbuseIPDB, OTX, ThreatFox, Shodan, passive DNS, cert transparency |
| **Processing** | IOC extraction, defanging, deduplication via CTI Toolkit pipeline |
| **Analysis** | Behavioral mapping, infrastructure pivoting, TTP correlation |
| **Production** | Structured report with MITRE ATT&CK mapping, PDF generated via TI Report Builder |
| **Dissemination** | Published in this repository with full artifact set |

---

## Report Structure

Each report is organized in its own folder:

```
reports/
└── NN_YYYY-MM_[ThreatName]/
    ├── report.md           # Full technical analysis
    ├── report.pdf          # Formatted PDF (TI Report Builder)
    ├── iocs.txt            # Defanged indicators of compromise
    ├── mitre_mapping.json  # ATT&CK techniques in structured format
    ├── references.txt      # Sources and external references
    └── screenshots/        # Visual evidence from analysis
```

---

## MITRE ATT&CK Coverage

Techniques documented across all reports:

| Technique ID | Name | Tactic | Reports |
|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Initial Access | 01 |
| T1204 | User Execution | Execution | 01 |
| T1027 | Obfuscated Files or Information | Defense Evasion | 01 |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | 01 |
| T1003 | OS Credential Dumping | Credential Access | 01 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | 01 |

---

## Tooling

Reports are produced using the [CTI Toolkit](https://github.com/Higor1912/cti-toolkit) — a modular threat intelligence automation pipeline:

| Module | Purpose |
|--------|---------|
| `feed_aggregator` | Collects IOCs from public feeds (Feodo, URLhaus, OTX, etc.) |
| `ioc_enricher` | Enriches IOCs via VirusTotal, AbuseIPDB, Shodan |
| `ttp_mapper` | Maps free-text reports to ATT&CK techniques (offline, TF-IDF) |
| `report_builder_cli` | Assembles pipeline output into structured report JSON |
| TI Report Builder | Generates formatted PDF reports |

---

## About

This repository is part of my public CTI portfolio. All analyses are based on open-source intelligence (OSINT) and are published for educational and professional demonstration purposes.

**Author:** Higor Silva  
**Focus:** Operational Threat Intelligence · Adversary Tracking · Infrastructure Analysis · ATT&CK Mapping  
**Contact:** [LinkedIn](https://www.linkedin.com/in/higor-silva-sec)

---

> IOCs are defanged throughout all reports. Do not use them in production environments without proper validation.
