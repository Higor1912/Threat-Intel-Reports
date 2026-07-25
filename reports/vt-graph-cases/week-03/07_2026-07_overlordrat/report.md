# Threat Intelligence Report: OverlordRAT

**ID:** week-03/07_2026-07_overlordrat
**Data:** 25/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como OverlordRAT via assinatura no MalwareBazaar, com 9 detecções entre vendors e 39 regras YARA associadas. O nome do arquivo, `Cleaner.exe`, segue o padrão clássico de ferramenta falsa de limpeza de sistema, isca recorrente para RATs distribuídos como utilitários gratuitos de otimização.

Esta investigação resolve uma pendência em aberto desde a semana 2 desta série e reformula a interpretação de um padrão que já havia aparecido duas vezes antes. Entre os dropped files do executável principal está um script PowerShell, e esse script específico é a peça que faltava para explicar a correlação de infraestrutura encontrada entre ValleyRAT (semana 1) e ScarfaceStealer (semana 2). O script contata diretamente tanto `cl-glcb907925.gcdn.co` quanto `cl-glcb907925.globalcdn.co`, os dois domínios quase idênticos que apareceram separadamente nessas duas investigações anteriores. Isso muda a leitura do achado: não são duas campanhas coincidentemente compartilhando infraestrutura, é o mesmo script utilitário genérico sendo reaproveitado como componente em cadeias de infecção de famílias completamente diferentes, cada uma contatando uma variação levemente diferente do mesmo domínio de CDN.

A escala desse reaproveitamento é a maior confirmada nesta série até agora. O grafo lista, no limite de exibição de 20 itens por relação, 20 arquivos diferentes que usam esse script como execution parent, cobrindo praticamente todos os tipos de arquivo já vistos nesta série: executáveis PE, instaladores MSI, arquivos ZIP, planilhas XLS, JavaScript e até outros scripts PowerShell. Como o grafo trunca a exibição em 20, o número real de arquivos que passam por este mesmo script é provavelmente maior. O script também contata 20 IPs e 20 domínios, misturando infraestrutura legítima da Microsoft e Akamai, provável ruído de verificação de conectividade, com os dois domínios de CDN já mencionados.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `2d9adcb653a222351652077abc838e027fa814f120741c7fb4f14d71d03f9fa0` |
| MD5 | `f3a81cd70d0c86700e45b9de40644c87` |
| Nome do arquivo | `Cleaner.exe` |
| Tamanho | 20.822.016 bytes |
| Primeira submissão | 25/07/2026 10:29:04 UTC |
| Detecção | 9 vendors |
| Regras YARA associadas | 39 |

---

## 3. O Script Compartilhado Entre Semanas

| Campo | Valor |
|---|---|
| SHA256 | `96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7` |
| Tipo | PowerShell |
| Detecção própria | Nenhuma |
| Presença anterior nesta série | Bundled file sem expansão no relatório de Vidar (semana 3, mesmo dia anterior) |

### 3.1 Domínios contatados (20, com destaque para os dois já vistos nesta série)

| Domínio | Detecção | Observações |
|---|---|---|
| `cl-glcb907925.gcdn.co` | Positiva | Idêntico ao domínio identificado na investigação de ValleyRAT (semana 1). |
| `cl-glcb907925.globalcdn.co` | Nenhuma | Idêntico ao domínio identificado na investigação de ScarfaceStealer (semana 2). |
| `api.msn.com`, `assets.msn.com`, `svc.ha-teams.office.com`, `svc.ms-acdc-teams.office.com` | Nenhuma | Serviços legítimos da Microsoft, provável ruído de verificação de conectividade. |
| `a1666.dscr.akamai.net`, `a1672.dscr.akamai.net`, `e592.d.akamaiedge.net` | Nenhuma | Infraestrutura Akamai, mesmo padrão de ruído. |
| 5 entradas de resolução reversa (`in-addr.arpa`) | Nenhuma | Consistente com o mesmo padrão de fingerprinting via PTR já observado na investigação de Vidar, mais cedo nesta mesma semana. |

### 3.2 IPs contatados (20)

Majoritariamente um bloco contíguo `208.89.72.0/24`, com 9 dos 20 endereços apresentando detecção positiva, além de infraestrutura Cloudflare e Fastly sem detecção.

### 3.3 Execution Parents (20 exibidos, provavelmente mais no total)

| Tipo | Quantidade na amostra de 20 |
|---|---|
| PE EXE | 8 |
| PowerShell | 5 |
| MSI | 1 |
| ZIP | 1 |
| LNK | 1 |
| JavaScript | 1 |
| XLS | 1 |
| Demais | 2 |

A diversidade de tipos de arquivo usando o mesmo script como estágio confirma que ele funciona como uma peça de infraestrutura genérica e comercializada ou compartilhada, não como um componente exclusivo de uma família específica. Os hashes seguem o mesmo padrão de prefixo com múltiplos zeros à esquerda já observado nos clusters de ArkeiStealer (semana 1) e do dropper de CVE-2017-11882 (semana 3, mesma semana), o que reforça a suspeita, já registrada naquele relatório, de que esse padrão pode ser artefato da forma como o VT Graph nomeia ou trunca certos conjuntos de relação, e não necessariamente uma convenção do operador. Vale investigação dedicada em uma próxima rodada.

---

## 4. Demais Dropped Files e Bundled Files

| SHA256 | Tipo | Detecção |
|---|---|---|
| `45c1baafb659e7cf65c2fff11a2cb9a0c113f4452e022de4d3216a17f79a96fe` | PE EXE | Positiva, mas sem relações de rede próprias além das já do executável principal. |
| `a7de5177c68a64bd48b36d49e2853799f4ebcfa8e4761f7cc472f333dc5f65cf` | Não informado | Nenhuma |
| `16829cae274604e970a66059dbcba2fe1aa34334b86b2a76c8e2ac66f0ce77f9` | CSV | Nenhuma |

Os 10 bundled files do executável principal trouxeram pouco detalhe adicional, majoritariamente sem atributos no export atual, à exceção de uma imagem ISO.

---

## 5. Infraestrutura de Rede Direta do Executável Principal

| Indicador | Detecção | Observações |
|---|---|---|
| `77.42.23.173` | Nenhuma | Finlândia, único IP contatado diretamente pelo executável raiz. |

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Nome de arquivo temático de ferramenta falsa de limpeza de sistema. |
| Ingress Tool Transfer | T1105 | Uso do script PowerShell compartilhado como estágio de distribuição para múltiplos tipos de payload. |
| Web Service | T1102 | Reaproveitamento confirmado dos domínios de CDN já vistos em duas investigações anteriores desta série. |
| Virtualization/Sandbox Evasion | T1497 | Padrão de resolução reversa de DNS, consistente com o comportamento já documentado na investigação de Vidar. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): 2d9adcb653a222351652077abc838e027fa814f120741c7fb4f14d71d03f9fa0
SHA256 (script compartilhado entre múltiplas semanas): 96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7

Domínios de CDN compartilhados (confirmados em 3 investigações desta série):
cl-glcb907925.gcdn.co
cl-glcb907925.globalcdn.co

Bloco de IPs com detecção positiva:
208.89.72.101
208.89.72.105
208.89.72.107
208.89.72.71
```

---

## 8. Recomendações

1. Tratar o script `96ad1146...` como indicador de hunting de altíssima prioridade em toda a base de relatórios desta série, dado seu papel confirmado como elo entre pelo menos quatro investigações distintas ao longo de três semanas.
2. Bloquear os dois domínios de CDN e o bloco `208.89.72.0/24` nos controles de perímetro.
3. Revisar retroativamente os relatórios de ValleyRAT (semana 1) e ScarfaceStealer (semana 2) para adicionar uma nota cruzada referenciando este achado como explicação da correlação já documentada ali.
4. Investigar o padrão de prefixo com zeros à esquerda nos hashes de execution parents como possível artefato do próprio VT Graph, não do operador, antes de tratá-lo como assinatura de campanha em relatórios futuros.
5. Considerar o tráfego para os domínios da Microsoft, Akamai e as entradas de resolução reversa como ruído esperado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura OverlordRAT).
Correlação cruzada com os relatórios 03_2026-07_valleyrat (semana 1), 04_2026-07_scarfacestealer (semana 2) e 01_2026-07_vidar (semana 3) desta mesma série.
