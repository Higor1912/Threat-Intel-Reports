# Feed Diário — IOCs Maliciosos 2026-05-04

**Author:** Higor Silva
**Date:** May/2026
**TLP:** GREEN
**Version:** 1.0

---

## 1. Executive Summary

Em 4 de maio de 2026, o pipeline de coleta automatizada identificou 305 indicadores de comprometimento provenientes de feeds públicos de threat intelligence, dos quais 283 foram classificados como maliciosos após enriquecimento via VirusTotal e AbuseIPDB. O conjunto inclui 5 endereços IP associados a infraestrutura de Comando e Controle (C2) do malware Emotet, coletados via Feodo Tracker, e 300 URLs de phishing ativas identificadas pelo OpenPhish.

A análise das URLs revela dois padrões predominantes: campanhas de credential harvesting contra usuários de plataformas de redes sociais (Meta/Facebook, Instagram) e serviços de streaming (Netflix, Amazon), e campanhas de roubo de carteiras de criptomoeda, com páginas falsas imitando Ledger, Trezor, MetaMask e exchanges diversas. Destaca-se o uso extensivo de infraestrutura legítima de hospedagem — Vercel, GitHub Pages, Webflow, Cloudflare Workers e IPFS — como vetor de distribuição, técnica que dificulta o bloqueio por reputação de domínio. Recomenda-se o bloqueio imediato dos indicadores nos controles perimetrais e verificação de logs de proxy e DNS para acessos históricos.

---

## 2. Threat Description

| Attribute | Detail |
|-----------|--------|
| **Threat Type** | Phishing / Credential Harvesting / C2 Infrastructure |
| **Target** | Multiple sectors — social media users, streaming subscribers, crypto holders |
| **Motivation** | Financial |
| **Attack Vector** | Phishing links via email/social media |
| **Associated Malware** | Emotet (C2 IPs) |
| **Threat Actor** | Unknown |
| **Confidence Level** | Medium |
| **Collection Date** | 2026-05-04 |

---

## 3. Technical Analysis

### 3.1 Indicators of Compromise (IOCs)

| Type | Count | Classification |
|------|-------|----------------|
| IPs (C2 Emotet) | 5 | Malicious (4), Suspicious (1) |
| URLs (Phishing) | 300 | Malicious (283), Suspicious (2), Clean (15) |
| **Total** | **305** | **283 Malicious** |

> Full IOC list available in [iocs.txt](./iocs.txt).

---

### 3.2 Observed Behavior

- **Credential Harvesting:** Phishing pages cloning Netflix, Amazon, Instagram, Facebook, and banking portals to steal login credentials
- **Crypto Wallet Theft:** Fake pages impersonating Ledger, Trezor, MetaMask, and crypto exchanges targeting wallet seed phrases
- **C2 Communication:** Emotet-associated IPs actively beaconing via HTTP/HTTPS
- **Infrastructure Abuse:** Threat actors hosting phishing pages on legitimate platforms (Vercel, GitHub Pages, Webflow, Netlify, Cloudflare Workers, IPFS, GoDaddy Sites) to evade domain reputation blocks
- **Typosquatting:** Domains mimicking Meta (`invoice-ads-manager[.]com`, `accounts-admin-agency[.]com`) and Microsoft (`authorised-support[.]com`)

---

### 3.3 Infrastructure Analysis

**C2 Infrastructure (Emotet):**

| IP | Reputation | Source |
|----|-----------|--------|
| `162.243.103.246` | Malicious | Feodo Tracker |
| `50.16.16.211` | Malicious | Feodo Tracker |
| `34.204.119.63` | Suspicious | Feodo Tracker |
| `178.62.3.223` | Malicious | Feodo Tracker |
| `27.133.154.218` | Malicious | Feodo Tracker |

**Phishing Hosting Platforms Abused:**

| Platform | Count (approx.) |
|----------|----------------|
| Vercel | ~40 URLs |
| GitHub Pages | ~25 URLs |
| Webflow | ~20 URLs |
| GoDaddy Sites | ~15 URLs |
| Netlify | ~10 URLs |
| Cloudflare Workers | ~8 URLs |
| IPFS | ~5 URLs |
| Other | ~177 URLs |

---

### 3.4 Tools Used in Analysis

| Category | Tool | Purpose |
|----------|------|---------|
| Feed Collection | Feed Aggregator (CTI Toolkit) | OpenPhish + Feodo Tracker ingestion |
| IOC Enrichment | VirusTotal, AbuseIPDB | Detection scoring and verdict |
| ATT&CK Mapping | Manual analysis + ttp_mapper.py | TTP correlation |
| Report Generation | TI Report Builder | PDF output |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Procedure |
|--------|-----------|----|-----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | 300 phishing URLs distributed via email/social media impersonating major platforms |
| Resource Development | Link Target | T1608.005 | Phishing infrastructure hosted on legitimate platforms to bypass domain reputation controls |
| Resource Development | Domains | T1583.001 | Typosquatting domains mimicking Meta, Microsoft, and crypto exchanges |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | 5 Emotet C2 IPs communicating via HTTP/HTTPS |

> Full mapping available in [mitre_mapping.json](./mitre_mapping.json).

---

## 5. Recommendations

### Immediate Actions
- Block all IOCs listed in this report at perimeter controls (firewall, proxy, DNS)
- Search SIEM/proxy logs for historical hits against listed indicators
- Alert SOC team for active monitoring

### Detection
- Create SIEM rules to detect connections to `invoice-ads-manager[.]com` and `accounts-admin-agency[.]com` subdomains
- Monitor DNS queries for typosquatting patterns against Meta/Microsoft brand names
- Flag outbound connections to Cloudflare Workers and IPFS gateways for unusual patterns

### Hardening
- Enable browser-based phishing protection and enforce Safe Browsing policies
- Implement DMARC/DKIM/SPF to reduce phishing email delivery
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
