# 🧠 Relatório de Threat Intelligence  
### Campanha de Phishing com Efimer Trojan e uso de IA no Brasil  
**Autor:** Higor Silva  
**Data:** Outubro/2025  
**Versão:** 1.0  

---

## 🧩 1. Sumário Executivo

Entre setembro e outubro de 2025, foram identificadas múltiplas campanhas de **phishing direcionadas a usuários brasileiros**, utilizando **ferramentas de inteligência artificial** para criar páginas falsas de instituições governamentais, como o Gov.br e o Detran.  
Essas campanhas estão associadas à disseminação do **Efimer Trojan**, malware com foco em **roubo de credenciais e carteiras de criptomoeda**.

As campanhas exploram **técnicas de SEO poisoning** para ganhar visibilidade em buscadores e atrair vítimas para os domínios falsos.  
A análise indica que cerca de **5.000 vítimas** já foram afetadas, com **impacto financeiro e exposição de dados pessoais**.

---

## 🔍 2. Descrição da Ameaça

| Atributo | Detalhe |
|-----------|----------|
| **Tipo de ameaça** | Campanha de phishing e malware (Efimer Trojan) |
| **Alvo** | Usuários brasileiros |
| **Motivação** | Financeira |
| **Vetor de ataque** | E-mails de phishing, sites falsificados, SEO poisoning |
| **Malware associado** | Efimer Trojan |
| **Impacto estimado** | Roubo de credenciais, dados pessoais e criptomoedas |

As páginas fraudulentas foram geradas com auxílio de ferramentas de IA, permitindo alta similaridade visual com sites legítimos e dificultando a detecção por usuários.  
Além disso, algumas instâncias do Efimer Trojan foram distribuídas via **torrents maliciosos** e **sites WordPress comprometidos**.

---

## 🧠 3. Análise Técnica

### 🔸 3.1 Indicadores de Comprometimento (IOCs)
| Tipo | Valor | Observação |
|------|--------|------------|
| Domínio | `govbr-login[.]com` | Página phishing |
| Domínio | `brdetran-check[.]net` | Clonagem de Detran |
| IP | `185.203.118.44` | C2 suspeito associado ao Efimer Trojan |
| Hash (SHA256) | `3f4a6c2d0e3b3b8e1bde68fa8f1b91df4cc3456cfd2347a0efab1c38c08f71b6` | Amostra analisada no VirusTotal |
| URL | `https[:]//govbr-login[.]com/valida-cpf` | Endpoint de coleta de dados |

> **Fontes:** VirusTotal, OTX, ThreatFox, TheHackerNews (2025).

---

### 🔸 3.2 Comportamento Observado
- Download e execução de binário ofuscado em lote.
- Tentativa de persistência via chave de registro `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- Comunicação HTTP com C2 sobre porta 8080.
- Exfiltração de credenciais armazenadas no Chrome e carteiras de criptomoedas locais.

---

### 🔸 3.3 Ferramentas Utilizadas na Análise
| Categoria | Ferramenta | Finalidade |
|------------|-------------|-------------|
| IOC Lookup | VirusTotal, OTX, ThreatFox | Identificação e correlação |
| Sandbox | Any.Run, Hybrid Analysis | Análise dinâmica do Trojan |
| WHOIS / DNS | Whois.domaintools, VirusTotal | Verificação de registros |
| MITRE Mapping | attack.mitre.org | Mapeamento de TTPs |

---

## 🎯 4. Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Descrição |
|--------|----------|----|------------|
| Initial Access | Phishing via link | T1566.002 | Envio de e-mails falsos contendo links para páginas clonadas |
| Execution | User Execution | T1204 | Usuário executa binário malicioso baixado |
| Credential Access | Credential Dumping | T1003 | Roubo de credenciais armazenadas |
| Exfiltration | Exfiltration Over HTTP | T1041 | Envio de dados para o C2 |
| Defense Evasion | Obfuscation / Packing | T1027 | Arquivo executável ofuscado para evitar detecção |

---

## 🧱 5. Avaliação e Impacto

- **Impacto financeiro:** Roubo de valores em criptomoedas e tentativas de fraude via PIX.  
- **Impacto reputacional:** Confusão de usuários e possível perda de confiança em instituições públicas.  
- **Impacto técnico:** Possível infecção de endpoints e persistência local.  

---

## 🛡️ 6. Recomendações

### Para Usuários Finais
- Evitar clicar em links enviados por e-mail ou mensagens de texto.  
- Validar domínios antes de inserir dados sensíveis.  
- Usar autenticação multifator (MFA) sempre que possível.  
- Manter antivírus e sistema operacional atualizados.

### Para Organizações
- Monitorar domínios similares a oficiais (typosquatting).  
- Configurar regras de detecção no SIEM para URLs e IPs listados.  
- Solicitar derrubada de páginas fraudulentas a provedores.  
- Aplicar políticas de DNS filtering e e-mail sandboxing.

---

## 🧾 7. Apêndice Técnico

### 7.1 Hashes 

3f4a6c2d0e3b3b8e1bde68fa8f1b91df4cc3456cfd2347a0efab1c38c08f71b6

### 7.2 Domínios Observados

govbr-login[.]com
brdetran-check[.]net

### 7.3 Indicadores Relacionados

185.203.118.44

---

> **Referências:**  
> - [The Hacker News – AI Tools Fuel Brazilian Phishing Scam (2025)](https://thehackernews.com/2025/08/ai-tools-fuel-brazilian-phishing-scam.html)  
> - [MITRE ATT&CK Matrix](https://attack.mitre.org)  
> - [VirusTotal](https://www.virustotal.com)  
> - [AlienVault OTX](https://otx.alienvault.com)  

---

📄 **Status:**  
Relatório elaborado com base em fontes abertas (OSINT).  
Uso permitido para fins educacionais e demonstração de capacidade analítica.
