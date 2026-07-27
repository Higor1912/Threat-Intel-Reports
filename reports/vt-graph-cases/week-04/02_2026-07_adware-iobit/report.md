# Threat Intelligence Report: Adware.IObit

**ID:** week-04/02_2026-07_adware-iobit
**Data:** 27/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Adware.IObit via assinatura no MalwareBazaar, com 6 detecções entre vendors e 22 regras YARA associadas. Vale uma distinção importante logo de início: IObit é uma empresa de software legítima, conhecida por produtos como Advanced SystemCare e Driver Booster, e os dois domínios contatados diretamente sob esse nome (`stats.iobit.com` e `update.iobit.com`) não apresentam detecção. O problema não está no software original, está no instalador que o embrulha. Esse é o padrão clássico de redes de afiliados de pagamento por instalação, que empacotam software legítimo junto de componentes adicionais indesejados ou maliciosos para monetizar cada download.

O tamanho do arquivo, cerca de 37 MB, e o volume de 10 dropped files, incluindo um script PowerShell e uma imagem JPEG com detecção positiva (possível uso de esteganografia ou apenas recurso de interface reaproveitado de forma suspeita), são consistentes com esse tipo de empacotador.

O achado mais expressivo veio de dois IPs hospedados na Holanda, contatados diretamente pela amostra. Juntos, eles formam o maior hub de distribuição compartilhada já identificado nesta série. O primeiro é contatado por 21 outros arquivos rastreados no grafo, e sozinho concentra 20 arquivos comunicantes confirmados, majoritariamente instaladores MSI. O segundo é contatado por 12 outros arquivos, com 11 comunicantes confirmados, também dominados por MSI. A composição fortemente concentrada em instaladores MSI, quase todos com detecção positiva, é a assinatura esperada de uma rede de distribuição de adware em escala, não de uma campanha isolada.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `3da1a4045d67c272137310c4df4ef6dfd0fbae684ac8c0fc76b4f2e31eb8138a` |
| MD5 | `068fe402eb8cdbb0fe21f972ac4a23fa` |
| Nome do arquivo | `068fe402eb8cdbb0fe21f972ac4a23fa.exe` (nome idêntico ao hash MD5) |
| Tamanho | 37.555.107 bytes |
| Primeira submissão | 27/07/2026 14:05:08 UTC |
| Detecção | 6 vendors |
| Regras YARA associadas | 22 |

---

## 3. Dropped Files (10)

| SHA256 | Tipo | Detecção |
|---|---|---|
| `4843f743b07faea86d7aa88d535709d0c965f38f3412bd1f19701124da662606` | PE EXE | Positiva |
| `eff5486e20cf31cc3339528dbe84170ac9a67da6b2af9a2d94ae7db8105739f4` | PE EXE | Positiva |
| `1ac31f6f78de13a9f10d86d1a67580a9e29bbd6df2a5b39e8d875897681b317a` | JPEG | Positiva |
| `0fa9b28d3bb8e455ad61735f5259d5d9b8f65bcefa44f83f69db8a4ca451e5bd` | PE DLL | Nenhuma |
| `15c35c5abf7bab8d1375f5622e31da14fd027ae1046b8a6ddfd74263fa34eda6` | PE DLL | Nenhuma |
| `e27cf7f42f25844308544dfbc6091576b19139ed24687220a0564daf1f694553` | PE DLL | Nenhuma |
| `47a558c58b5a79df1bc7183b71a4e7fe2da84f7c52c4548f080e00f6ebc68fbc` | PowerShell | Nenhuma |
| Demais 3 arquivos | Não informado | Sem atributos no export |

A imagem JPEG com detecção positiva é um detalhe fora do padrão comum e vale investigação dedicada para confirmar se carrega payload via esteganografia ou se a detecção é falso positivo ligado a metadados suspeitos.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (3)

| Domínio | Detecção | Observações |
|---|---|---|
| `stats.iobit.com` | Nenhuma | Infraestrutura legítima da IObit. |
| `update.iobit.com` | Nenhuma | Infraestrutura legítima da IObit. |
| `vpnl.net` | Positiva | Nome sugestivo de serviço de VPN, possivelmente parte da oferta adicional empacotada pelo instalador. |

### 4.2 Hub de Distribuição: dois IPs na Holanda

**IP 157.20.182.20**

| Métrica | Valor |
|---|---|
| Arquivos que também contatam esse IP (além da amostra atual) | 21 |
| Arquivos comunicantes confirmados | 20, todos com detecção positiva |
| Composição | 15 MSI, 5 PE EXE |
| Registro de WHOIS histórico | 1 |

**IP 158.94.210.247**

| Métrica | Valor |
|---|---|
| Arquivos que também contatam esse IP (além da amostra atual) | 12 |
| Arquivos comunicantes confirmados | 11, sendo 10 com detecção positiva |
| Composição | 4 CSV, 3 MSI, 3 PE EXE, 1 VBA |
| Registro de WHOIS histórico | 1 |
| Certificado SSL histórico | 1 |

A predominância de instaladores MSI comunicando com ambos os IPs é o indicador mais forte de que essa infraestrutura serve como backend de uma rede de distribuição de adware em escala, atendendo múltiplos pacotes de instalação diferentes a partir do mesmo backend.

### 4.3 Demais IPs contatados (6)

Faixas Cloudflare, Akamai e AWS sem detecção, prováveis dependências legítimas de CDN.

### 4.4 URLs Contatadas (3)

Todas as 3 URLs têm detecção positiva, sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Instalador empacotado disfarçado de software legítimo. |
| Web Service | T1102 | Reaproveitamento confirmado dos dois IPs holandeses por 33 arquivos maliciosos adicionais combinados. |
| Ingress Tool Transfer | T1105 | Queda de componentes adicionais, incluindo DLLs, script PowerShell e executáveis. |
| Masquerading | T1036 | Uso do nome e domínios legítimos da IObit como fachada para o pacote real distribuído. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 3da1a4045d67c272137310c4df4ef6dfd0fbae684ac8c0fc76b4f2e31eb8138a

Hub de distribuição:
157.20.182.20
158.94.210.247

Domínio suspeito: vpnl.net
```

---

## 7. Recomendações

1. Bloquear os dois IPs holandeses nos controles de perímetro, dado o volume combinado de 33 arquivos maliciosos adicionais confirmados na mesma infraestrutura.
2. Orientar usuários a baixar produtos IObit exclusivamente do site oficial, já que o problema está no instalador de terceiros, não no software original.
3. Investigar a imagem JPEG com detecção positiva para confirmar ou descartar uso de esteganografia.
4. Verificar a presença das DLLs e do script PowerShell dropados no ambiente monitorado.
5. Considerar o tráfego para `stats.iobit.com` e `update.iobit.com` como legítimo, sem necessidade de bloqueio, mantendo o foco de resposta na infraestrutura holandesa.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Adware.IObit).
