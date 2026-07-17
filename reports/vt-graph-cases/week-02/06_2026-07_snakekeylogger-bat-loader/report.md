# Threat Intelligence Report: SnakeKeylogger (variante disfarçada de .bat)

**ID:** week-02/06_2026-07_snakekeylogger-bat-loader
**Data:** 17/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

Essa é a segunda amostra da família SnakeKeylogger analisada nesta série, mas ao contrário da primeira (relatório 02, semana 2), que não tinha nenhuma relação de rede própria e dependia inteiramente de uma coleção pública para contexto, esta amostra trouxe uma cadeia de rede completa e diretamente rastreável no grafo. A confirmação veio via MalwareBazaar, com 15 detecções entre vendors.

O primeiro ponto de atenção é o próprio arquivo. Ele se chama `HG9765445678900.bat`, mas o VT identifica seu conteúdo real como um executável PE, não como um script batch. Essa dupla identidade, extensão de script e conteúdo de PE, é uma técnica de disfarce para passar despercebido por filtros de anexo de email que costumam ser mais permissivos com arquivos `.bat` do que com `.exe`.

A infraestrutura de rede confirma o padrão documentado da família de forma direta, sem depender de coleções externas. A amostra contata `api.telegram.org`, já com detecção positiva, e o IP `149.154.166.110`, pertencente à faixa oficial de servidores do Telegram, confirmando exfiltração ou controle via bot do Telegram para esta amostra específica. Paralelamente, ela contata dois serviços de checagem de IP público, `checkip.dyndns.org` e `reallyfreegeoip.org`, ambos com detecção positiva, comportamento típico de fingerprinting da vítima antes do envio dos dados coletados. Um conjunto de IPs na infraestrutura de nuvem da Oracle, distribuídos entre Brasil, Japão, Estados Unidos e Alemanha, também aparece contatado, com um deles reaproveitado por outros 2 arquivos maliciosos no mesmo grafo.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (disfarçado com extensão .bat) |
| SHA256 | `c363e567a04e86db78f38568d6aad75186719deac66459276dbba3c458151e70` |
| MD5 | `622ccff40973d7099893300bfcecc434` |
| Nome do arquivo | `HG9765445678900.bat` |
| Tamanho | 154.624 bytes |
| Primeira submissão | 17/07/2026 06:03:19 UTC |
| Detecção | 15 vendors |
| Regras YARA associadas | 5 |

---

## 3. Execution Parent e Bundled Files

| SHA256 | Tipo | Observações |
|---|---|---|
| `1518c556bd665b7dc0f7ec9a949a03036696f67784155b6df744e9f26185cfd2` | ZIP | Execution parent, com detecção positiva própria. Dropa a amostra principal e um segundo arquivo sem atributos, além de contatar `assets.msn.com` (ruído) e dois IPs Akamai sem detecção. |

Os 4 bundled files da amostra principal trouxeram pouco detalhe no export atual: um XML sem detecção e três arquivos sem atributos disponíveis.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (4)

| Domínio | Detecção | Observações |
|---|---|---|
| `api.telegram.org` | Positiva | Canal de exfiltração ou controle via bot do Telegram, comportamento documentado da família. |
| `checkip.dyndns.org` | Positiva | Checagem de IP público da vítima antes da exfiltração. |
| `checkip.dyndns.com` | Nenhuma | Mesmo serviço, variação de subdomínio. |
| `reallyfreegeoip.org` | Positiva | Serviço de geolocalização por IP, mesmo propósito de fingerprinting. |

### 4.2 IPs contatados (8)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `149.154.166.110` | NL | Positiva | Faixa oficial de servidores do Telegram. |
| `193.122.6.168` | DE | Positiva | Infraestrutura de nuvem Oracle. Reaproveitado por outros 2 arquivos maliciosos no mesmo grafo. |
| `158.101.44.242` | US | Positiva | Infraestrutura de nuvem Oracle. |
| `132.226.247.73` | BR | Positiva | Infraestrutura de nuvem Oracle. |
| `132.226.8.169` | JP | Positiva | Infraestrutura de nuvem Oracle. |
| `104.21.67.152`, `172.67.177.134` | ZZ | Nenhuma | Faixa Cloudflare, provável proxy dos serviços de checagem de IP. |
| `193.122.130.0` | US | Nenhuma | Infraestrutura de nuvem Oracle, sem detecção. |

O espalhamento de IPs Oracle Cloud por quatro países diferentes (Alemanha, Estados Unidos, Brasil e Japão), todos com detecção positiva, sugere uso de múltiplas regiões da mesma nuvem para distribuir a carga de comunicação ou dificultar bloqueio geográfico único.

### 4.3 URL Contatada

Uma URL com detecção positiva foi listada, sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | T1036.005 | Conteúdo PE disfarçado com extensão `.bat` para evadir filtros de anexo. |
| Exfiltration Over Web Service | T1567 | Comunicação confirmada com o IP oficial do Telegram e com `api.telegram.org`. |
| System Location Discovery | T1614 | Uso de dois serviços distintos de checagem de IP público para fingerprinting da vítima. |
| Input Capture: Keylogging | T1056.001 | Comportamento central e confirmado da família SnakeKeylogger. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): c363e567a04e86db78f38568d6aad75186719deac66459276dbba3c458151e70
SHA256 (ZIP execution parent): 1518c556bd665b7dc0f7ec9a949a03036696f67784155b6df744e9f26185cfd2

IP oficial Telegram: 149.154.166.110
IPs Oracle Cloud com detecção positiva:
193.122.6.168
158.101.44.242
132.226.247.73
132.226.8.169

Domínios de fingerprinting:
checkip.dyndns.org
reallyfreegeoip.org
```

---

## 7. Recomendações

1. Sinalizar anexos de email com extensão `.bat` mas assinatura de conteúdo PE como indicador direto de disfarce, independente da detecção de antivírus.
2. Monitorar tráfego de saída para `api.telegram.org` e para a faixa oficial de IPs do Telegram originado de processos não relacionados ao cliente oficial.
3. Bloquear os quatro IPs Oracle Cloud listados nos IoCs, priorizando o IP alemão, já reaproveitado por outros 2 arquivos maliciosos no mesmo grafo.
4. Tratar o acesso a `checkip.dyndns.org` e `reallyfreegeoip.org` por processos não relacionados a diagnóstico de rede como sinal comportamental de triagem.
5. Comparar esta cadeia de infraestrutura com a coleção pública "Snake Keylogger" usada no relatório 02 desta mesma semana, para verificar se os IPs Oracle Cloud aqui identificados já constavam naquele levantamento agregado.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura SnakeKeylogger).
