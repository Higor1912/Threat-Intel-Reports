# Threat Intelligence Report: Gh0stRAT (segunda amostra desta série)

**ID:** week-05/03_2026-08_gh0strat-ii
**Data:** 05/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Gh0stRAT via assinatura no MalwareBazaar, com 10 detecções entre vendors e 17 regras YARA associadas. Essa é a segunda vez que a família aparece nesta série, depois da investigação da semana 2, e o grafo conecta diretamente as duas pontas de correlações já documentadas ao longo das últimas cinco semanas.

O primeiro ponto é a coleção pública associada ao hash: 银狐 (SilverFox), o mesmo cluster de ator chinês identificado na investigação de ValleyRAT na semana 1, que distribui justamente ValleyRAT, Gh0stRAT e PurpleFox de forma combinada. Essa é a primeira vez nesta série que uma coleção documentada permite ligar diretamente duas investigações de famílias diferentes ao mesmo agrupamento de ameaça nomeado publicamente, reforçando a hipótese levantada na semana 1 sobre esse cluster continuar ativo.

O segundo ponto é uma correlação direta de arquivo: um dos dropped files desta amostra, `388a796580234efc95f3b1c70ad4cb44bfddc7ba0f9203bf4902b9929b136f95`, é exatamente o mesmo hash já registrado como dropped file na primeira investigação de Gh0stRAT desta série. Nesse caso a explicação mais provável não é reaproveitamento entre famílias diferentes, como visto em correlações anteriores, mas sim consistência do próprio builder da família entre duas campanhas distintas ao longo do tempo.

O C2 confirmado é o domínio `kkagag.net`, sem tema aparente, resolvendo para um IP no Japão com detecção positiva.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b` |
| MD5 | `b3c9d1993a05188c4bce23a34aa1d549` |
| Nome do arquivo | `rLobO7.exe` |
| Tamanho | 21.356.892 bytes |
| Primeira submissão | 05/08/2026 00:48:47 UTC |
| Detecção | 10 vendors |
| Regras YARA associadas | 17 |

---

## 3. Correlações com Investigações Anteriores

| Indicador | Tipo | Correlação |
|---|---|---|
| Coleção 银狐 (SilverFox) | Coleção pública | Mesmo cluster identificado na investigação de ValleyRAT, semana 1. |
| `388a796580234efc95f3b1c70ad4cb44bfddc7ba0f9203bf4902b9929b136f95` | Dropped file (PE EXE, sem detecção) | Hash idêntico ao dropped file já registrado na primeira investigação de Gh0stRAT, semana 2 desta série. |

---

## 4. Demais Dropped Files (5)

| SHA256 | Tipo | Detecção |
|---|---|---|
| `83004a532887c305588c0080281a775158e30891b064a2cf3d8025f95e83d815` | PE EXE | Positiva |
| `ca6d9ccbd533140aaf867152eb8f2b5d2e8c997989c94de64c2225b19f4fa0d6` | PE DLL | Positiva |
| `789380fcad5a5f182e373884f345d09fbffb967d033380ce3bc8cdc4e35d13fe`, `a277e920cec99564cf9a50fd7bb62a4da64c4b74ba767bf761433b0374b20750` | Não informado | Sem atributos no export |

---

## 5. Infraestrutura de Rede

### 5.1 Domínios contatados (2)

| Domínio | Detecção | Observações |
|---|---|---|
| `kkagag.net` | Nenhuma | C2 provável, apesar da ausência de detecção direta no domínio. |
| `assets.msn.com` | Nenhuma | Ruído esperado de telemetria. |

### 5.2 IPs contatados (5)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `137.220.134.169` | JP | Positiva | Provável resolução do domínio `kkagag.net`. |
| `23.55.236.130`, `23.55.236.131`, `23.55.236.136`, `23.55.236.141` | US | Nenhuma | Faixa Akamai, ruído esperado. |

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o domínio e IP de C2 no Japão. |
| Web Service | T1102 | Reaproveitamento confirmado de componente entre duas campanhas da mesma família ao longo desta série. |
| Ingress Tool Transfer | T1105 | Cinco dropped files, dois com detecção positiva. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): 8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b
SHA256 (dropped file recorrente entre campanhas Gh0stRAT): 388a796580234efc95f3b1c70ad4cb44bfddc7ba0f9203bf4902b9929b136f95

Domínio de C2: kkagag.net
IP de C2: 137.220.134.169
```

---

## 8. Recomendações

1. Bloquear `kkagag.net` e o IP `137.220.134.169` nos controles de perímetro.
2. Registrar formalmente a ligação entre esta investigação, a de Gh0stRAT da semana 2 e a de ValleyRAT da semana 1 através do cluster SilverFox, consolidando as três como parte do mesmo agrupamento de ameaça mais amplo.
3. Verificar a presença das duas DLLs/executáveis com detecção positiva no ambiente monitorado.
4. Tratar o hash `388a796580234efc95f3b1c70ad4cb44bfddc7ba0f9203bf4902b9929b136f95` como indicador de builder da família Gh0stRAT, útil para hunting retroativo em outras amostras.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Gh0stRAT).
Correlação cruzada com os relatórios 03_2026-07_valleyrat (semana 1) e 03_2026-07_gh0strat (semana 2) desta mesma série.
