# Threat Intelligence Report: BlakcSeeStealer

**ID:** week-04/01_2026-07_blakcseestealer
**Data:** 26/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como BlakcSeeStealer via assinatura no MalwareBazaar, com 8 detecções entre vendors e 14 regras YARA associadas. O nome do arquivo, `msys-magic-1.dll`, imita a nomenclatura de bibliotecas legítimas do MSYS2, ambiente Unix-like para Windows amplamente usado por desenvolvedores, um disfarce consistente com técnica de DLL sideloading, na qual um software legítimo carrega a biblioteca maliciosa por engano ao procurar componentes por nome em seu diretório de execução.

O comportamento de rede direto da amostra é enxuto e previsível: contato com três serviços de checagem de IP público (`api.ipify.org`, `ip-api.com`, `ipify.org`), fingerprinting padrão antes de prosseguir com a coleta de dados. O achado relevante está em um dos IPs contatados, hospedado no Reino Unido, que se revela um ponto ativo tanto de distribuição quanto de infraestrutura histórica de phishing. Esse endereço funciona como referrer file de 10 arquivos maliciosos distintos, incluindo a própria amostra analisada, e seu histórico de resolução DNS soma 20 domínios quase inteiramente temáticos de golpes de restituição de imposto de renda, com nomes como `process-taxrebate.top`, `claim-incometax.top` e `process-refund.top`, a maioria já com detecção positiva.

Esse padrão de infraestrutura compartilhada entre entrega de malware e phishing temático de restituição fiscal é uma combinação que ainda não havia aparecido nesta série, e sugere um operador ou serviço de distribuição que atende tanto campanhas de engenharia social quanto de malware diretamente a partir da mesma infraestrutura.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE DLL |
| SHA256 | `77be91fc4ee0154ee4b6d0a48c596de2bffca40f1aebbf888b9ee2f3e09c89e9` |
| MD5 | `58813057d929f6d79e69ffd26161fad1` |
| Nome do arquivo | `msys-magic-1.dll` |
| Tamanho | 4.045.824 bytes |
| Primeira submissão | 26/07/2026 16:24:11 UTC |
| Detecção | 8 vendors |
| Regras YARA associadas | 14 |

---

## 3. Infraestrutura de Rede

### 3.1 Domínios e IPs de fingerprinting

| Indicador | Detecção | Observações |
|---|---|---|
| `api.ipify.org` | Nenhuma | Checagem de IP público. |
| `ip-api.com` | Positiva | Checagem de IP público e geolocalização. |
| `ipify.org` | Positiva | Mesmo serviço do primeiro item, domínio raiz. |
| `208.95.112.1` | Positiva | IP hospedeiro do serviço ip-api.com. |

### 3.2 IP de Distribuição e Phishing: 94.183.168.16 (Reino Unido)

| Métrica | Valor |
|---|---|
| Arquivos maliciosos para os quais funciona como referrer file | 10, incluindo a amostra atual |
| Domínios no histórico de resolução | 20 |
| Domínios com detecção positiva | 14 de 20 |
| Registro de WHOIS histórico | 1 |
| Certificado SSL histórico | 1 |

**Domínios do histórico de resolução (tema de restituição fiscal)**

```
mahbucutz.com
www.mahbucutz.com
process-taxrebate.top
www.process-taxrebate.top
revenue.process-taxrebate.top
process-taxclaim.top
www.process-taxclaim.top
revenue.process-taxclaim.top
claim-incometax.top
www.claim-incometax.top
revenue.claim-incometax.top
claim-rebate.top
www.claim-rebate.top
revenue.claim-rebate.top
process-refund.top
www.process-refund.top
revenue.process-refund.top
process-rebate.top
www.process-rebate.top
revenue.process-rebate.top
```

O padrão de três variações por domínio base (raiz, `www.` e `revenue.`) sugere geração automatizada em lote a partir de um pequeno conjunto de templates, típico de kits de phishing comercializados.

**Outros arquivos que usam o mesmo IP como referrer**

| SHA256 |
|---|
| `cc158ba548d9bc877497173fc34d19e96bb238fe4ce13fb9d2821aae9c1af9cd` |
| `698d4d474414ddb3d01f06a359871b039e4076e03b90acf0bf2a08703e1b4a8b` |
| `e85e4507e93231d930721b18879370df6dfd4ff0e947e1e7f7a563f3f2e8084e` |
| `a453c32e5ef903d180d097d723a7007ec56b628bb27dfcbad59b3b23100570e3` |
| `1be4f99c31eb3b05bd6b8bae05d9c6e46499a33dbc3c899a9259cc0167411cba` |
| `72fe08950673cff7bbb84bbdf89c5f8f1601ab326ff12202c38f8c875bbd9807` |
| `2d4d058331c5bdee61dc6dd26ced4312b102d562833a29119f2285677e90bf66` |
| `72d5024635812edd74b80e2407dc41a7b29e85bfa4605919f93e836c40a683e5` |
| `a240dc87029954830c540d251458dd409d67e9faa68aea74d81fb7c110e0a98f` |

Todos os 9 arquivos adicionais são executáveis PE com detecção positiva própria.

### 3.3 URLs Contatadas (4)

3 das 4 URLs têm detecção positiva, sem texto completo disponível no export atual.

---

## 4. Dropped Files e Bundled Files

Os 20 dropped files e 7 dos 8 bundled files não trouxeram atributos detalhados no export atual, à exceção de uma imagem ISO entre os bundled files, sem detecção. Recomenda se checagem manual direta no VT Graph para tipificar esse volume de arquivos.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Hijack Execution Flow: DLL Side Loading | T1574.002 | Nome de arquivo imitando biblioteca legítima do MSYS2. |
| System Location Discovery | T1614 | Uso de múltiplos serviços de checagem de IP público antes da coleta de dados. |
| Phishing | T1566 | Infraestrutura compartilhada com domínios temáticos de restituição fiscal, associada ao mesmo IP de distribuição. |
| Ingress Tool Transfer | T1105 | Papel do IP britânico como referrer file confirmado para 10 arquivos maliciosos distintos. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 77be91fc4ee0154ee4b6d0a48c596de2bffca40f1aebbf888b9ee2f3e09c89e9

IP de distribuição e phishing: 94.183.168.16

Domínios de phishing fiscal (detecção positiva):
process-taxrebate.top
process-taxclaim.top
claim-incometax.top
claim-rebate.top
process-refund.top
process-rebate.top
mahbucutz.com
```

---

## 7. Recomendações

1. Bloquear o IP `94.183.168.16` e os domínios de phishing fiscal listados nos controles de perímetro.
2. Orientar usuários sobre o tema de golpes de restituição de imposto de renda associado a essa infraestrutura, já que combina entrega de malware com engenharia social financeira.
3. Investigar os outros 9 arquivos que usam o mesmo IP como referrer para mapear se pertencem à mesma campanha ou a clientes diferentes do mesmo serviço de distribuição.
4. Verificar a presença de DLLs com nomes imitando bibliotecas legítimas (MSYS2, ou outras) no ambiente monitorado, técnica de sideloading que costuma passar despercebida em varreduras superficiais.
5. Expandir manualmente os 20 dropped files e os 7 bundled files sem atributos no export atual diretamente no VT Graph.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura BlakcSeeStealer).
