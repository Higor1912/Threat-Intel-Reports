# Threat Intelligence Report: Socks5Systemz

**ID:** week-03/06_2026-07_socks5systemz
**Data:** 24/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Socks5Systemz via assinatura no MalwareBazaar, com 10 detecções entre vendors e 6 regras YARA associadas, além de uma coleção pública dedicada confirmando a mesma atribuição. Socks5Systemz é um botnet cuja função central é transformar máquinas infectadas em nós de proxy SOCKS5, revendidos posteriormente como serviço de proxy residencial para outros operadores, um modelo de monetização diferente da maioria das famílias já cobertas nesta série, que priorizam roubo direto de dados ou extorsão.

O nome do arquivo veio genérico, apenas `file`, sem tema de isca aparente. O executável principal em si tem pegada de rede mínima, mas seus dois execution parents, ambos executáveis PE com detecção positiva, compartilham uma infraestrutura de rede quase idêntica entre si, o que sugere que ambos vêm do mesmo builder ou operador. Os dois contatam o mesmo conjunto de URLs com detecção positiva, o mesmo IP na Holanda e o mesmo IP na Turquia, e ambos abusam de `drive.usercontent.google.com` para hospedagem de conteúdo, um padrão de abuso de armazenamento legítimo já recorrente nesta série desde a investigação de WannaCry na semana anterior.

Dois domínios chamam atenção específica. `tzpx.courses`, com detecção positiva, usa um TLD fora do padrão comum de C2, possivelmente escolhido para evitar listas de bloqueio genéricas voltadas a TLDs mais associados a abuso. O segundo, `ymaoc0ocqe2qesg4sgui6uiwk8wkymaymaoc0ocqe2qesg4sgui6uiwk8wk.com`, é uma string longa e repetitiva que sugere geração automática, possivelmente saída de um algoritmo de geração de domínios (DGA) ou um esquema de codificação de identificador de campanha embutido no próprio nome.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `1a02f5724eaaa775d4718dd266d630b1f8cdbc218516c0afd70800240a07a150` |
| MD5 | `da3734f8176354f8f88f17651e56e91b` |
| Nome do arquivo | `file` (nome genérico) |
| Tamanho | 4.345.613 bytes |
| Primeira submissão | 24/07/2026 09:30:40 UTC |
| Detecção | 10 vendors |
| Regras YARA associadas | 6 |

---

## 3. Execution Parents com Infraestrutura Compartilhada

| SHA256 | Tipo |
|---|---|
| `50c0740a65c8a7bf043e26fe01add8e28254fc52c935686b8d87b99d2fc3a5ef` | PE EXE, detecção positiva |
| `9d07be223ead089ff7b27bf5882d8059295776032d765097023e3163311ae264` | PE EXE, detecção positiva |

### 3.1 Indicadores compartilhados entre os dois

| Indicador | Tipo | Detecção |
|---|---|---|
| `158.94.209.95` | IP (Holanda) | Positiva |
| `176.53.159.222` | IP (Turquia) | Positiva |
| `drive.usercontent.google.com` | Domínio | Nenhuma, abuso de serviço legítimo |
| `usercontent.google.com` | Domínio | Nenhuma |
| 5 URLs com detecção positiva | URL | Positiva em ambos |

### 3.2 Indicadores exclusivos do primeiro execution parent (50c0740a)

| Indicador | Detecção |
|---|---|
| `tzpx.courses` | Positiva |
| `microsoft.com` | Nenhuma |
| `158.94.209.95`, `167.99.78.100` (Cingapura), `172.253.155.132` (EUA) | Positiva |

### 3.3 Indicadores exclusivos do segundo execution parent (9d07be22)

| Indicador | Detecção |
|---|---|
| `ymaoc0ocqe2qesg4sgui6uiwk8wkymaymaoc0ocqe2qesg4sgui6uiwk8wk.com` | Nenhuma, padrão de nome sugere DGA |
| `c.pki.goog`, `o.pki.goog` | Nenhuma, infraestrutura de certificado do Google |
| `142.251.163.132`, `192.178.209.132` (faixa Google) | Positiva |
| `8.8.8.8` | Positiva |

A sobreposição quase total de indicadores entre os dois execution parents, com apenas pequenas variações, é consistente com duas compilações diferentes do mesmo builder, geradas próximas no tempo ou pelo mesmo operador.

---

## 4. Dropped Files do Executável Principal (20)

| Composição | Quantidade |
|---|---|
| PE DLL | 12 |
| PE EXE | 3 |
| Texto | 2 |
| LNK | 1 |
| ICO | 1 |
| PowerShell | 1 |

Apenas 2 dos 20 dropped files carregam detecção individual positiva, ambos PE, consistentes com os módulos que efetivamente implementam a funcionalidade de proxy no sistema comprometido. O arquivo LNK entre os dropados sugere mecanismo de persistência via atalho de inicialização.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Proxy | T1090 | Comportamento central e documentado da família Socks5Systemz, transformando o host em nó de proxy SOCKS5. |
| Web Service | T1102 | Abuso de `drive.usercontent.google.com` para hospedagem de conteúdo. |
| Dynamic Resolution | T1568 | Domínio com padrão de nome sugestivo de geração automática. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com os IPs de C2 na Holanda e na Turquia. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 1a02f5724eaaa775d4718dd266d630b1f8cdbc218516c0afd70800240a07a150
SHA256 (execution parent 1): 50c0740a65c8a7bf043e26fe01add8e28254fc52c935686b8d87b99d2fc3a5ef
SHA256 (execution parent 2): 9d07be223ead089ff7b27bf5882d8059295776032d765097023e3163311ae264

IPs de C2 compartilhados:
158.94.209.95
176.53.159.222

Domínios:
tzpx.courses
ymaoc0ocqe2qesg4sgui6uiwk8wkymaymaoc0ocqe2qesg4sgui6uiwk8wk.com
```

---

## 7. Recomendações

1. Bloquear os IPs `158.94.209.95` e `176.53.159.222` e o domínio `tzpx.courses` nos controles de perímetro.
2. Monitorar tráfego de saída incomum via SOCKS5 originado de hosts corporativos, comportamento característico desta família mesmo sem exfiltração direta de dados.
3. Verificar a presença das duas DLLs ou executáveis com detecção positiva entre os dropped files no ambiente monitorado.
4. Investigar o domínio de padrão repetitivo como possível saída de DGA, comparando com outras amostras futuras desta família para confirmar o algoritmo de geração.
5. Considerar o tráfego para `drive.usercontent.google.com`, `microsoft.com` e a infraestrutura de certificado do Google como ruído esperado, sem necessidade de bloqueio isolado.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Socks5Systemz).
Coleção pública do VT Graph: "Socks5Systemz Malware".
