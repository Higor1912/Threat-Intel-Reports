# Threat Intelligence Report: Loda

**ID:** week-05/07_2026-08_loda
**Data:** 08/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Loda via assinatura no MalwareBazaar, com 14 detecções entre vendors e 9 regras YARA associadas. O nome do arquivo, `msedge.exe`, imita diretamente o executável do Microsoft Edge, disfarce simples mas eficaz para passar despercebido em uma lista de processos.

O C2 confirmado é `thispc.net` e seu subdomínio `my.thispc.net`, resolvendo para um IP em Singapura. Esse endereço é o achado mais relevante da investigação: comunica com 12 arquivos maliciosos distintos, todos com detecção positiva, cobrindo executáveis PE, um XML e um atalho LNK, composição consistente com uma cadeia de infecção que combina múltiplos formatos de entrega em torno da mesma infraestrutura de C2.

Entre os 18 bundled files, um chama atenção por classificação de tipo incomum: um arquivo marcado como `android` aparece junto aos recursos tipicamente esperados (ícones, textos, um script PowerShell). Não é possível confirmar, apenas com os metadados do grafo, se isso indica um componente multiplataforma real ou apenas uma classificação heurística equivocada, e fica registrado como ponto de checagem manual.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `edc48d610c3410f12653b2e7ada4f66ed8cfc7bed556f215620b5ec747b6c1fc` |
| MD5 | `a74c2f34562da758b23a0697466847fc` |
| Nome do arquivo | `msedge.exe` |
| Tamanho | 1.480.704 bytes |
| Primeira submissão | 08/08/2026 17:36:15 UTC |
| Detecção | 14 vendors |
| Regras YARA associadas | 9 |

---

## 3. Dropped Files (5) e Bundled Files (18)

Entre os dropped files, 4 não trouxeram atributos detalhados no export atual. Entre os 18 bundled files, a maioria são ícones e arquivos de texto sem detecção, além de um script PowerShell sem detecção própria e o arquivo classificado como `android` mencionado no sumário executivo.

---

## 4. Infraestrutura de Rede

### 4.1 C2: thispc.net / my.thispc.net / 207.148.77.235 (Singapura)

| Métrica | Valor |
|---|---|
| Arquivos comunicantes confirmados | 12, todos com detecção positiva |
| Composição | 9 PE EXE, 1 XML, 1 LNK, mais a amostra atual |
| Domínios resolvidos | `thispc.net`, `my.thispc.net`, ambos com detecção positiva |
| Outros arquivos que também contatam o IP diretamente | 2 |
| Registro de WHOIS histórico | Presente |

A combinação de LNK e XML entre os arquivos comunicantes sugere uma cadeia de infecção que combina atalhos de inicialização e arquivos de configuração em torno da mesma infraestrutura, além dos executáveis PE esperados.

### 4.2 Demais Indicadores

| Indicador | Detecção | Observações |
|---|---|---|
| `162.159.36.2` | Nenhuma | Faixa Cloudflare, ruído esperado. |

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | T1036.005 | Nome de arquivo imitando o Microsoft Edge. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o C2 dedicado em Singapura. |
| Web Service | T1102 | Reaproveitamento confirmado do mesmo domínio e IP por 12 arquivos maliciosos adicionais. |
| Ingress Tool Transfer | T1105 | Cadeia de infecção combinando LNK, XML e executáveis PE. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): edc48d610c3410f12653b2e7ada4f66ed8cfc7bed556f215620b5ec747b6c1fc

Domínio de C2: thispc.net
Subdomínio de C2: my.thispc.net
IP de C2: 207.148.77.235
```

---

## 7. Recomendações

1. Bloquear `thispc.net`, `my.thispc.net` e o IP `207.148.77.235` nos controles de perímetro.
2. Investigar os outros 11 arquivos comunicantes confirmados para mapear a extensão completa da campanha.
3. Verificar manualmente o arquivo bundled classificado como `android`, para confirmar se representa um componente real multiplataforma ou classificação heurística imprecisa.
4. Sinalizar executáveis chamados `msedge.exe` fora do diretório de instalação legítimo do Microsoft Edge como indicador direto de triagem.
5. Expandir manualmente os 4 dropped files sem atributos remanescentes diretamente no VT Graph.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Loda).
