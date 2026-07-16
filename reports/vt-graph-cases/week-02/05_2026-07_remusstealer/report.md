# Threat Intelligence Report: RemusStealer

**ID:** week-02/05_2026-07_remusstealer
**Data:** 15/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

O achado central é um IP hospedado na Índia, `143.244.141.187`, contatado diretamente pela amostra e que se revela o hub de comando e controle mais ativo identificado em toda esta série até agora. Esse endereço comunica com 50 arquivos maliciosos distintos catalogados no grafo, entre executáveis PE, arquivos ZIP, um instalador MSI e bibliotecas DLL, todos com detecção positiva. Esse volume supera o do IP britânico visto na investigação de ArkeiStealer e o do hub indiano da investigação de ValleyRAT, ambas da semana anterior, tornando esse endereço o ponto de infraestrutura mais reaproveitado observado até agora nesta série.

O histórico de resolução DNS do IP soma 12 domínios, com pelo menos quatro já confirmados maliciosos: o próprio `zelpx.garden`, contatado diretamente pela amostra, além de `cloxaa.shop`, `falcoju.shop` e `estranat.biz`. Dois outros domínios chamam atenção pelo tema: `adminx.shipxpost.com` e `management.shipxpost.com`, ambos subdomínios de um serviço com nome que remete a rastreamento de encomendas, um tema clássico de isca de phishing voltado a notificações falsas de entrega.

O domínio de C2 também aparece como referrer file de 6 arquivos executáveis, todos com detecção positiva, reforçando que ele funciona como ponto de distribuição ativo, não apenas como canal de callback passivo.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `f0239fb8b03bd25c4631c7f4d02c7a5c462c215477f0eaf721656e51e3d79710` |
| MD5 | `fe5a98f5cfbe505df9ae7d9003fa3671` |
| Nome do arquivo | `file` (nome genérico, sem valor de isca aparente) |
| Tamanho | 3.610.960 bytes |
| Primeira submissão | 16/07/2026 10:26:43 UTC |
| Detecção | 5 vendors |
| Regras YARA associadas | 22 |

---

## 3. Bundled Files (10)

Todos os 10 arquivos bundled vieram sem atributos detalhados no export atual. Recomenda se checagem manual direta no VT Graph para tipo e detecção individual.

---

## 4. Infraestrutura de Rede da Amostra Principal

### 4.1 Domínios contatados (5)

| Domínio | Detecção | Observações |
|---|---|---|
| `zelpx.garden` | Positiva | C2 principal, detalhado na seção 5. |
| `accounts.google.com`, `play.google.com`, `www.gstatic.com` | Nenhuma | Serviços legítimos do Google, provável ruído ou checagem de conectividade. |
| `microsoft.com` | Nenhuma | Ruído esperado do sistema operacional. |

### 4.2 IPs contatados (10)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `143.244.141.187` | IN | Positiva | Hub de C2 principal, detalhado na seção 5. |
| `64.233.160.84`, `.100`, `.101`, `.102`, `.113`, `.138`, `.139` | US | Nenhuma | Faixa do Google, provável checagem de conectividade. |
| `74.125.127.94` | US | Nenhuma | Faixa do Google. |
| `224.0.0.251` | ZZ | Nenhuma | Multicast mDNS, ruído de rede local. |

### 4.3 URL contatada

O grafo lista uma URL contatada pela amostra, sem texto completo disponível no export atual.

---

## 5. IP de Comando e Controle: 143.244.141.187 (Índia)

Esse endereço é o achado mais relevante desta investigação.

**Volume de reaproveitamento:** 50 arquivos maliciosos distintos catalogados como communicating files, todos com detecção positiva, distribuídos entre PE EXE, ZIP, MSI e PE DLL. Esse é o maior número de arquivos comunicando com um único IP observado nesta série até agora.

**Histórico de resolução DNS (12 domínios)**

| Domínio | Detecção | Observações |
|---|---|---|
| `zelpx.garden` | Positiva | Contatado diretamente pela amostra principal. |
| `cloxaa.shop` | Positiva | |
| `falcoju.shop` | Positiva | |
| `estranat.biz` | Positiva | |
| `easxin.top` | Nenhuma | |
| `nexusw.top` | Nenhuma | |
| `calciy.xyz` | Nenhuma | |
| `hypfers.shop` | Nenhuma | |
| `adminx.shipxpost.com` | Nenhuma | Subdomínio com tema de rastreamento de encomendas, possível isca de phishing. |
| `management.shipxpost.com` | Nenhuma | Mesmo domínio base do item acima. |
| `www.autothat.com`, `autothat.com` | Nenhuma | Tema não identificado claramente. |

**Referrer files:** 6 arquivos executáveis, todos com detecção positiva, usaram esse domínio como origem de download, confirmando papel ativo na distribuição, não apenas em callback de C2.

**WHOIS e certificados:** 3 registros de WHOIS histórico e 1 certificado SSL histórico associados ao domínio `zelpx.garden`, valores completos disponíveis para consulta direta no VT Graph.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação direta com o IP de C2 na Índia. |
| Web Service | T1102 | Reaproveitamento confirmado do mesmo IP e domínio por 50 arquivos maliciosos distintos. |
| Phishing | T1566 | Domínios temáticos de rastreamento de encomendas associados à mesma infraestrutura de C2. |
| Ingress Tool Transfer | T1105 | Papel do domínio de C2 como referrer file de 6 executáveis adicionais. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): f0239fb8b03bd25c4631c7f4d02c7a5c462c215477f0eaf721656e51e3d79710

IP de C2: 143.244.141.187

Domínios maliciosos confirmados:
zelpx.garden
cloxaa.shop
falcoju.shop
estranat.biz
```

---

## 8. Recomendações

1. Bloquear o IP `143.244.141.187` e os quatro domínios confirmados maliciosos nos controles de perímetro.
2. Tratar esse IP como prioridade alta de hunting, dado o volume de 50 arquivos maliciosos distintos associados a ele, o maior nível de reaproveitamento de infraestrutura observado nesta série até o momento.
3. Investigar os subdomínios de `shipxpost.com`, já que o tema de rastreamento de encomendas sugere uma frente de phishing ainda não confirmada associada a essa infraestrutura.
4. Considerar o tráfego para os domínios e IPs do Google como ruído esperado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
