# Threat Intelligence Report: Stealc

**ID:** week-04/07_2026-08_stealc
**Data:** 01/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Stealc via assinatura no MalwareBazaar, com 10 detecções entre vendors e 4 regras YARA associadas. Esta é a segunda exportação desta investigação. A primeira veio sem nenhuma relação expandida, e esta segunda, já com o grafo corretamente expandido, revelou a maior concentração de correlações cruzadas com investigações anteriores já registrada nesta série.

Em vez de abrir uma infraestrutura nova, esta amostra funciona como um ponto de encontro entre pelo menos quatro clusters já documentados em semanas diferentes. Ela contata diretamente o domínio `cl-glcb907925.gcdn.co` e o IP `92.223.96.6`, a mesma dupla de indicadores que conecta ValleyRAT (semana 1), ScarfaceStealer (semana 2) e o script compartilhado do OverlordRAT (semana 3). Ela também contata o bloco `150.171.109.0/24` de servidores de saída de email da Microsoft, agora em sua quarta aparição confirmada nesta série, depois de ScarfaceStealer, SilentNet e Formbook. E, indo além da rede, dois de seus dropped files são hashes idênticos a componentes já vistos: um é exatamente o módulo de reconhecimento de rede local identificado na investigação de ArkeiStealer (semana 1), e o outro é um dos arquivos SQL dropados pela amostra de DojinerBackdoor, investigada apenas alguns dias atrás nesta mesma semana 4.

Além dessas correlações, a amostra contata um domínio próprio com detecção positiva, `play-update-store.com`, um typosquat evidente da Google Play Store, provável ponto de distribuição ou C2 dedicado a esta campanha específica de Stealc.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726` |
| MD5 | `9c1bee9ed7cc87bf6a874b71fea8e178` |
| Nome do arquivo | `file` (nome genérico) |
| Tamanho | 2.152.960 bytes |
| Primeira submissão | 01/08/2026 00:18:11 UTC |
| Última submissão | 01/08/2026 09:39:21 UTC |
| Detecção | 10 vendors |
| Regras YARA associadas | 4 |

---

## 3. Componentes Compartilhados com Investigações Anteriores

| SHA256 | Papel nesta amostra | Origem já documentada |
|---|---|---|
| `92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45` | Bundled file e dropped file | Módulo de reconhecimento de rede local (varredura `192.168.0.0/24`), identificado na investigação de ArkeiStealer, semana 1. |
| `c007da2e5fd780008f28336940b427c3bfd509c72a40bfb7759592149ff3606e` | Dropped file, tipo SQL | Um dos quatro arquivos SQL dropados pela amostra de DojinerBackdoor, semana 4, investigado dias antes deste caso. |

A recorrência do módulo de reconhecimento de rede local é particularmente relevante. Esse mesmo componente já havia aparecido em uma segunda ocasião nesta série, no PE dropado pelo dropper de CVE-2017-11882 (semana 3), que também apresentava o mesmo comportamento de varredura de `192.168.0.0/24`. Com esta terceira aparição, confirmada agora com o hash exato, fica estabelecido que esse módulo de varredura de rede local circula como componente independente entre famílias completamente diferentes: ArkeiStealer, o dropper via exploração de documento, e agora Stealc.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (10)

| Domínio | Detecção | Observações |
|---|---|---|
| `cl-glcb907925.gcdn.co` | Positiva | Idêntico ao domínio que conecta ValleyRAT (semana 1), ScarfaceStealer (semana 2) e o script do OverlordRAT (semana 3). |
| `play-update-store.com` | Positiva | Typosquat da Google Play Store, provável C2 ou distribuição dedicada desta campanha. |
| `a1672.dscr.akamai.net`, `ctldl.windowsupdate.com`, `windowsupdate.com`, `microsoft.com`, `nexusrules.officeapps.live.com` | Nenhuma | Ruído esperado de telemetria e atualização do Windows. |
| `c.pki.goog`, `pki.goog` | Nenhuma | Infraestrutura de certificado do Google. |
| `eip-terr-na.cdp1.digicert.com.akahost.net` | Nenhuma | Validação de certificado DigiCert. |

### 4.2 IPs contatados (18)

| IP | Detecção | Observações |
|---|---|---|
| `92.223.96.6` | Positiva | Mesmo IP que conecta ValleyRAT (semana 1) e ScarfaceStealer (semana 2). |
| `150.171.109.146` | Positiva | Bloco de saída de email da Microsoft, quarta aparição confirmada nesta série. |
| `150.171.110.210` | Positiva | Mesmo bloco. |
| `150.171.109.113`, `150.171.109.145`, `150.171.109.51`, `150.171.109.53`, `150.171.109.77`, `150.171.110.145` | Nenhuma | Mesmo bloco, sem detecção individual. |
| Demais 9 IPs | Nenhuma | Faixas Cloudflare, Akamai, Fastly e Google, ruído esperado. |

### 4.3 URLs Contatadas (6)

Nenhuma das 6 URLs apresentou detecção, sem texto completo disponível no export atual.

---

## 5. Demais Dropped Files e Bundled Files

| SHA256 | Observações |
|---|---|
| `331627bf72dde7064c97c0b07d080243257048c8726fb0cd22be8f13c904f370` | Sem atributos no export, presente tanto como bundled quanto como dropped file. |
| `0f5b1b2e2b844c3179cbbb82ee999cf52475ba4946c23711be04a6e01635e1f2`, `13a37456232ade30656939cebc01934b6c859d38324e3df2295733971f467eef`, `1aee0d953742d91462c8cd9fa992ed4aec3a3a0482cfee6f27beec34c995ad7b`, `8aa1d45b3e749a1163e6859bcc64f69b066740878ebc30e90c309ab7ddfb04cb` | Sem atributos no export. |

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Network Service Discovery | T1046 | Reaproveitamento confirmado do módulo de varredura de rede local já visto em ArkeiStealer e no dropper de CVE-2017-11882. |
| Web Service | T1102 | Reaproveitamento confirmado de domínio, IP e bloco Microsoft já documentados em quatro investigações anteriores desta série. |
| Masquerading | T1036 | Domínio typosquat da Google Play Store. |
| Credentials from Password Stores | T1555 | Comportamento central e documentado da família Stealc. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): 11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726
SHA256 (módulo de reconhecimento de rede, terceira aparição na série): 92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45
SHA256 (arquivo SQL compartilhado com DojinerBackdoor): c007da2e5fd780008f28336940b427c3bfd509c72a40bfb7759592149ff3606e

Domínio de C2 dedicado: play-update-store.com
Domínio da rede compartilhada entre semanas: cl-glcb907925.gcdn.co
IP da rede compartilhada entre semanas: 92.223.96.6
IP do bloco Microsoft (quarta aparição): 150.171.109.146
```

---

## 8. Recomendações

1. Bloquear `play-update-store.com` nos controles de perímetro como C2 dedicado desta campanha.
2. Tratar o conjunto `cl-glcb907925.gcdn.co` / `92.223.96.6` / `150.171.109.0/24` como um único grupo de infraestrutura de hunting prioritário para toda a base de relatórios desta série, já que agora conecta cinco investigações distintas ao longo de três semanas.
3. Consolidar formalmente, em um documento à parte, o mapa de componentes compartilhados identificados até agora nesta série (o script do OverlordRAT, o INI do Amadey/DojinerBackdoor, e agora o módulo de rede local do ArkeiStealer/CVE-2017-11882/Stealc), já que o volume de correlações cruzadas começa a justificar uma visão consolidada própria.
4. Verificar a presença do módulo de varredura de rede local em qualquer host que também tenha apresentado indicadores de ArkeiStealer ou do dropper de CVE-2017-11882, dado o reaproveitamento confirmado do mesmo componente.
5. Expandir manualmente os 4 arquivos sem atributos remanescentes diretamente no VT Graph.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo, segunda exportação já expandida).
MalwareBazaar (confirmação da assinatura Stealc).
Correlação cruzada com os relatórios 06_2026-07_arkeistealer (semana 1), 03_2026-07_valleyrat (semana 1), 04_2026-07_scarfacestealer (semana 2), 04_2026-07_cve-2017-11882-xlam-dropper (semana 3), 07_2026-07_overlordrat (semana 3) e 05_2026-07_dojinerbackdoor (semana 4) desta mesma série.
