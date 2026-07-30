# Threat Intelligence Report: DojinerBackdoor

**ID:** week-04/05_2026-07_dojinerbackdoor
**Data:** 30/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como DojinerBackdoor via assinatura no MalwareBazaar, com 10 detecções entre vendors e 4 regras YARA associadas. O nome do arquivo veio idêntico ao próprio hash SHA256, sem tema de isca. A confirmação de família, no entanto, é direta e sem ambiguidade: o domínio de C2 principal é `dojiner.at`, com dois subdomínios adicionais também flagged, `da.dojiner.at` e `ph.dojiner.at`, todos batendo diretamente com o nome da assinatura.

Entre os 20 dropped files, quatro DLLs carregam detecção positiva própria, além de quatro arquivos SQL sem detecção individual, um tipo de arquivo incomum entre os dropados desta série até agora e que sugere componente de armazenamento ou exfiltração estruturada de dados coletados, mais elaborado que o simples envio de arquivo de texto ou JSON visto em outras famílias.

O achado mais relevante desta investigação, porém, é uma correlação direta com a semana anterior. Um dos arquivos INI dropados por esta amostra, `255a65d30841ab4082bd9d0eea79d49c5ee88f56136157d8d6156aef11c12309`, é exatamente o mesmo hash do arquivo de configuração dropado pela amostra de Amadey investigada na semana 3 desta série. Duas famílias completamente diferentes, DojinerBackdoor e Amadey, compartilhando um componente de configuração idêntico byte a byte, entre semanas distintas. Esse é mais um caso, seguindo o padrão já estabelecido com o script do OverlordRAT, de um componente específico servindo como elo entre investigações que pareceriam não relacionadas à primeira vista.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `61858e50c96a6f37957e1d6e3249ddb49ebd5c592ddce8dacf039404897afe45` |
| MD5 | `2980c33b9f0de038fc408602fbf34187` |
| Nome do arquivo | Idêntico ao hash SHA256, sem tema de isca |
| Tamanho | 123.904 bytes |
| Primeira submissão | 30/07/2026 06:23:27 UTC |
| Detecção | 10 vendors |
| Regras YARA associadas | 4 |

---

## 3. Dropped Files (20)

| SHA256 | Tipo | Detecção | Observações |
|---|---|---|---|
| `1d25a6e27e8c1d0e6a477319d664e1549b539cdc87ce3df449bac4d3d4bfa12e` | PE DLL | Positiva | |
| `6e35a2ea945c53377ef4534ced5254a59e2ccb7b021194aafeb70a5ecd41f460` | PE DLL | Positiva | |
| `c0745e07474b41ee398a8e11734f28ed20a0c21c7be23e6269b783b8753bcdac` | PE DLL | Positiva | |
| `d5dfb4547fa18eaa838ffd2f47b5b43f0be02fa0c6f378101b457282b12a0d98` | PE DLL | Positiva | |
| `255a65d30841ab4082bd9d0eea79d49c5ee88f56136157d8d6156aef11c12309` | INI | Nenhuma | Hash idêntico ao arquivo de configuração dropado pela amostra de Amadey, semana 3 desta série. |
| `0b27061804cdc55501fd8901a01907c5876d1a460ea899097cfa8ff469f9cc3c` | XML | Nenhuma | |
| `8297a7698f19bb81539a18363db100c55e357fa73f773c2b883d2c4161f6a259` | SQL | Nenhuma | |
| `b281ce54125d4250a80f48fcc02a8eea53f2c35c3b726e2512c3d493da0013bf` | SQL | Nenhuma | |
| `ba7eb45b7e9b6990bc63be63836b74fa2ccb64dcd0c199056b6ae37b1ae735f2` | SQL | Nenhuma | |
| `c007da2e5fd780008f28336940b427c3bfd509c72a40bfb7759592149ff3606e` | SQL | Nenhuma | |
| Demais 10 arquivos | Não informado | Sem atributos no export | |

Os quatro arquivos SQL entre os dropados são um componente incomum nesta série. A hipótese mais provável é uso de um banco de dados local (SQLite ou similar) para armazenamento estruturado de credenciais ou dados coletados antes da exfiltração, mais elaborado que o armazenamento em texto simples visto em outras famílias já cobertas.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (6)

| Domínio | Detecção | Observações |
|---|---|---|
| `dojiner.at` | Positiva | Domínio de C2 principal, nome direto da família. |
| `da.dojiner.at` | Positiva | Subdomínio de C2. |
| `ph.dojiner.at` | Positiva | Subdomínio de C2. |
| `ip-api.com` | Positiva | Checagem de IP público e geolocalização. |
| `assets.adobedtm.com`, `assets.msn.com` | Nenhuma | Ruído esperado de telemetria. |

### 4.2 IPs contatados (6)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `196.251.121.186` | Seychelles | Positiva | Registro de WHOIS histórico associado. |
| `208.95.112.1` | US | Positiva | IP hospedeiro do serviço ip-api.com. |
| `64.89.160.67` | US | Positiva | Registro de WHOIS e certificado SSL histórico associados. |
| `23.195.81.72`, `23.195.81.99` | US | Nenhuma | Faixa Akamai, ruído esperado. |
| `8.8.8.8` | US | Nenhuma | Resolver público. |

### 4.3 URLs Contatadas (9)

7 das 9 URLs apresentam detecção positiva, sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o domínio de C2 e seus subdomínios. |
| System Location Discovery | T1614 | Checagem de IP público via `ip-api.com`. |
| Data Staged: Local Data Staging | T1074.001 | Uso de arquivos SQL entre os dropados, indicativo de armazenamento estruturado local antes da exfiltração. |
| Web Service | T1102 | Componente de configuração compartilhado com a investigação de Amadey, semana 3 desta série. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 61858e50c96a6f37957e1d6e3249ddb49ebd5c592ddce8dacf039404897afe45
SHA256 (arquivo de configuração compartilhado com Amadey): 255a65d30841ab4082bd9d0eea79d49c5ee88f56136157d8d6156aef11c12309

Domínios de C2:
dojiner.at
da.dojiner.at
ph.dojiner.at

IPs com detecção positiva:
196.251.121.186
208.95.112.1
64.89.160.67
```

---

## 7. Recomendações

1. Bloquear `dojiner.at` e seus subdomínios nos controles de perímetro.
2. Investigar os quatro arquivos SQL dropados para confirmar a estrutura de dados armazenada, priorizando identificação de tipo de credencial ou informação coletada.
3. Registrar formalmente a correlação com o relatório de Amadey (semana 3) no repositório, já que o arquivo de configuração compartilhado sugere possível origem comum de builder ou reaproveitamento de código entre as duas famílias.
4. Abrir diretamente no VT Graph as URLs com detecção positiva para obter o texto completo, já que provavelmente revelam endpoints específicos de C2.
5. Verificar a presença das quatro DLLs com detecção positiva no ambiente monitorado.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura DojinerBackdoor).
Correlação cruzada com o relatório 05_2026-07_amadey (semana 3) desta mesma série.
