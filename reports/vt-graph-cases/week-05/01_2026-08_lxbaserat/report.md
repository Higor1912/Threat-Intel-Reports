# Threat Intelligence Report: LxBaseRAT

**ID:** week-05/01_2026-08_lxbaserat
**Data:** 03/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como LxBaseRAT via assinatura no MalwareBazaar, com 7 detecções entre vendors e 2 regras YARA associadas. O nome do arquivo, `3aka3_17954113028072026_Azotny_Zavod_LLP.js`, usa tema corporativo russo, "Azotny Zavod" remete a uma planta industrial de nitrogênio, isca consistente com phishing direcionado a contatos comerciais de língua russa.

Esta é a primeira investigação da semana 5 e já abre com duas correlações diretas com investigações anteriores. Entre os 20 dropped files está o mesmo script PowerShell (`96ad1146...`) que conecta ValleyRAT (semana 1), ScarfaceStealer (semana 2) e o OverlordRAT (semana 3), agora confirmado circulando também nesta amostra, em uma família e uma semana completamente diferentes. O segundo achado é o IP `208.95.112.1`, hospedeiro do serviço `ip-api.com`, idêntico ao já registrado na investigação de DojinerBackdoor na semana 4.

O domínio de C2 dedicado, `lxrrxl.ydns.eu`, usa o mesmo provedor de DNS dinâmico (`ydns.eu`) já visto no conjunto de domínios associados à coleção pública de SnakeKeylogger na semana 2, embora sem overlap direto de subdomínio específico. Esse domínio é contatado por 6 arquivos diferentes neste grafo, incluindo a amostra atual, confirmando reaproveitamento de infraestrutura mesmo dentro desta única investigação.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | JavaScript |
| SHA256 | `6d1d682be71ae048aa3c54806590c97efb7ab2e824f1a5ac98819f166903cf93` |
| MD5 | `5b1ecb218f51730dca6a4efdd022fd02` |
| Nome do arquivo | `3aka3_17954113028072026_Azotny_Zavod_LLP.js` |
| Tamanho | 1.909.131 bytes |
| Primeira submissão | 03/08/2026 11:27:09 UTC |
| Detecção | 7 vendors |
| Regras YARA associadas | 2 |

---

## 3. Componente Compartilhado com Investigações Anteriores

| SHA256 | Tipo | Origem já documentada |
|---|---|---|
| `96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7` | PowerShell | Script que conecta ValleyRAT (semana 1), ScarfaceStealer (semana 2) e é execution parent de dezenas de arquivos identificado em profundidade na investigação de OverlordRAT (semana 3). Esta é a quarta semana em que esse componente específico aparece na série. |

---

## 4. Dropped Files (20)

| SHA256 | Tipo | Detecção | Observações |
|---|---|---|---|
| `7ef99788da4eca57b2e24314caea39acc9a5d5532067574d44efef207fe86142` | VBA | Positiva | |
| `f89208d273bd1dffe636dbd9914528d07eb1911e727154215f619384cdce6fe9` | PowerShell | Positiva | Script distinto do componente compartilhado da seção 3. |
| `96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7` | PowerShell | Nenhuma | Componente compartilhado, ver seção 3. |
| `f5b9c0a4dd11ce495f64ea4a78511e0307bdbca9e7922af7b6e3946e136ea841` | VBA | Nenhuma | |
| `36cfebee53b718608c1922a5f6fa9414b1476a6cdf74dcfc409a74c2f5c84cd9`, `73853976fed1495aceeef5e62be0ea8bd9d62b1b688b91c8323c827dc8de59ce` | Texto | Nenhuma | |
| `0b33a715b8924b76d631e8ce8fe003a16ff4131a963462c9ed13c6ea045fc075` | CSV | Nenhuma | |
| Demais 13 arquivos | Não informado | Sem atributos no export | |

A combinação de VBA e PowerShell entre os dropados sugere uma cadeia de infecção em múltiplos estágios de script, com o JavaScript inicial orquestrando macros e scripts adicionais antes de qualquer binário compilado.

---

## 5. Infraestrutura de Rede

### 5.1 Domínio de C2: lxrrxl.ydns.eu

| Métrica | Valor |
|---|---|
| Arquivos que contatam esse domínio (incluindo a amostra atual) | 6 |
| Provedor | ydns.eu, serviço de DNS dinâmico gratuito |

O mesmo provedor `ydns.eu` já apareceu nesta série como parte do conjunto de domínios associados à coleção pública de SnakeKeylogger na semana 2, reforçando que esse serviço de DNS dinâmico continua sendo escolha recorrente entre operadores de RAT de baixo custo.

### 5.2 Demais Indicadores

| Indicador | Detecção | Observações |
|---|---|---|
| `ip-api.com` | Positiva | Checagem de IP público. |
| `208.95.112.1` | Positiva | IP hospedeiro do ip-api.com, idêntico ao registrado na investigação de DojinerBackdoor (semana 4). |
| `217.64.151.119` | Nenhuma | Suécia, sem detecção. |
| 1 URL contatada | Positiva | Sem texto completo disponível no export atual. |

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Tema de isca corporativa russa. |
| Ingress Tool Transfer | T1105 | Cadeia de infecção em múltiplos estágios de script (JavaScript, VBA, PowerShell). |
| Dynamic Resolution | T1568 | Uso de DNS dinâmico via ydns.eu para o domínio de C2. |
| System Location Discovery | T1614 | Checagem de IP público via ip-api.com. |
| Web Service | T1102 | Reaproveitamento confirmado do script PowerShell já documentado em três semanas anteriores desta série. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): 6d1d682be71ae048aa3c54806590c97efb7ab2e824f1a5ac98819f166903cf93
SHA256 (script compartilhado, quarta semana consecutiva de aparição): 96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7

Domínio de C2: lxrrxl.ydns.eu
IP hospedeiro compartilhado do ip-api.com: 208.95.112.1
```

---

## 8. Recomendações

1. Bloquear o domínio `lxrrxl.ydns.eu` nos controles de perímetro.
2. Continuar tratando o script `96ad1146...` como indicador de hunting permanente para toda a base de relatórios desta série, já confirmado em quatro semanas consecutivas.
3. Investigar os outros 5 arquivos que contatam o mesmo domínio de C2 para mapear se pertencem à mesma campanha.
4. Verificar a presença dos scripts VBA e PowerShell com detecção positiva no ambiente monitorado.
5. Orientar contatos comerciais de língua russa sobre o tema recorrente de documentos falsos de empresas industriais como vetor de phishing.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura LxBaseRAT).
Correlação cruzada com os relatórios 03_2026-07_valleyrat (semana 1), 04_2026-07_scarfacestealer (semana 2), 07_2026-07_overlordrat (semana 3) e 05_2026-07_dojinerbackdoor (semana 4) desta mesma série.
