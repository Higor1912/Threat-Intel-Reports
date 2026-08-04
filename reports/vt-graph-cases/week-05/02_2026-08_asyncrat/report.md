# Threat Intelligence Report: AsyncRAT

**ID:** week-05/02_2026-08_asyncrat
**Data:** 03/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como AsyncRAT via assinatura no MalwareBazaar, com 14 detecções entre vendors e 5 regras YARA associadas. O nome do arquivo, `Order no. 274419.exe`, segue o padrão clássico de phishing corporativo temático de pedido de compra, já recorrente nesta série.

Um detalhe curioso veio das coleções públicas associadas ao hash: ambas nomeiam a família como XWorm, não AsyncRAT. Isso não é necessariamente um erro de atribuição, XWorm é um fork derivado do código-base do AsyncRAT, e é comum que amostras compiladas a partir de builders modificados carreguem características de ambas as famílias na visão de diferentes analistas e ferramentas de classificação.

Outro achado de correlação: um dos dois dropped files da amostra, um arquivo de texto sem detecção, tem hash idêntico ao único dropped file registrado na investigação de Formbook, semana 3 desta série. Duas famílias de propósito bem diferente, um infostealer comercial e um RAT, compartilhando o mesmo componente de texto.

O C2 confirmado é `carrenzaalwarex.ddns.net`, resolvendo para um IP na Eslovênia que funciona como hub compartilhado por pelo menos 13 arquivos maliciosos adicionais, todos com detecção positiva, divididos entre executáveis PE e arquivos RAR.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `5b636ca0d5d324942c7ed1f8b194fa9d8ad64a8d77596e6fe36fcc4c2c2b1486` |
| MD5 | `d7940fcb7b48f07a6949c7e3d91b0aab` |
| Nome do arquivo | `Order no. 274419.exe` |
| Tamanho | 809.472 bytes |
| Primeira submissão | 03/08/2026 07:08:57 UTC |
| Detecção | 14 vendors |
| Regras YARA associadas | 5 |

---

## 3. Componente Compartilhado com Investigação Anterior

| SHA256 | Tipo | Origem já documentada |
|---|---|---|
| `7c207d29e8efc73141c4bdd33c763c4cd0286bd8c63e814e7fdec8c4129b7e51` | Texto | Único dropped file registrado na investigação de Formbook, semana 3 desta série. |

---

## 4. Coleções Associadas

| Coleção | Observações |
|---|---|
| XWorm Malware | Atribuição alternativa, consistente com XWorm ser um fork derivado do AsyncRAT. |
| XWorm | Segunda entrada, mesma atribuição alternativa. |

---

## 5. Dropped Files e Bundled Files

| SHA256 | Tipo | Detecção |
|---|---|---|
| `7c207d29e8efc73141c4bdd33c763c4cd0286bd8c63e814e7fdec8c4129b7e51` | Texto | Nenhuma, componente compartilhado (seção 3) |
| `f9f38fa1274e82957b6091c4488c7115ea7baebec14589f728f034b222742f07` | PowerShell | Positiva |

Os 15 bundled files são majoritariamente ícones sem detecção, incluindo um segundo script PowerShell sem detecção própria, consistentes com a interface gráfica padrão de um cliente RAT.

---

## 6. Infraestrutura de Rede

### 6.1 C2: carrenzaalwarex.ddns.net / 102.220.160.204 (Eslovênia)

| Métrica | Valor |
|---|---|
| Arquivos comunicantes confirmados | 13, todos com detecção positiva |
| Composição | 8 PE EXE, 5 RAR |
| Outros arquivos que também contatam o domínio ou IP diretamente | 6 |
| Registro de WHOIS histórico | Presente |

O uso de No-IP DDNS (`ddns.net`) para o domínio de C2 é consistente com o padrão de baixo custo já documentado em outras famílias desta série (localto.net no njRAT, ydns.eu no LxBaseRAT, .top no Amadey), reforçando que infraestrutura de DNS dinâmico gratuito continua sendo a escolha dominante entre operadores de RAT de menor orçamento.

---

## 7. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Tema de isca de pedido de compra corporativo. |
| Dynamic Resolution | T1568 | Uso de DNS dinâmico gratuito para o domínio de C2. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de C2 na Eslovênia. |
| Web Service | T1102 | Reaproveitamento confirmado do IP por 13 arquivos maliciosos adicionais e do dropped file de texto com a investigação de Formbook. |

---

## 8. IoCs Consolidados

```
SHA256 (amostra principal): 5b636ca0d5d324942c7ed1f8b194fa9d8ad64a8d77596e6fe36fcc4c2c2b1486
SHA256 (arquivo de texto compartilhado com Formbook): 7c207d29e8efc73141c4bdd33c763c4cd0286bd8c63e814e7fdec8c4129b7e51

Domínio de C2: carrenzaalwarex.ddns.net
IP de C2: 102.220.160.204
```

---

## 9. Recomendações

1. Bloquear `carrenzaalwarex.ddns.net` e o IP `102.220.160.204` nos controles de perímetro.
2. Investigar os outros 6 arquivos que contatam o mesmo domínio ou IP diretamente, para mapear a extensão real da campanha.
3. Registrar formalmente no repositório a correlação do arquivo de texto compartilhado com Formbook, seguindo o mesmo padrão já aplicado às correlações de Amadey/DojinerBackdoor.
4. Verificar a presença do script PowerShell com detecção positiva no ambiente monitorado.
5. Considerar a atribuição dupla AsyncRAT/XWorm ao configurar regras de detecção, já que builders modificados podem escapar de assinaturas voltadas a apenas uma das duas famílias.

---

## 10. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura AsyncRAT).
Correlação cruzada com o relatório 03_2026-07_formbook (semana 3) desta mesma série.
