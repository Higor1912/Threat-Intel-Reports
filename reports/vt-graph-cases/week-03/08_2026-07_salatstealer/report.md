# Threat Intelligence Report: SalatStealer

**ID:** week-03/08_2026-07_salatstealer
**Data:** 25/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como SalatStealer via assinatura no MalwareBazaar, com 11 detecções entre vendors e 61 regras YARA associadas, o maior número de regras de toda a série até agora. O nome do arquivo, `loader.exe`, é genérico, mas o domínio de C2 entrega a atribuição por conta própria: `sa1atik.cn` é um typosquat direto do nome da família, substituindo o "l" por "1".

O grafo revela um comportamento já visto antes nesta série, mas em uma variante diferente de blockchain. A amostra contata `tonapi.io` e `ton.access.orbs.network`, ambos endpoints de API da rede TON (The Open Network, a blockchain associada ao ecossistema Telegram), o segundo caso desta série de um stealer interagindo diretamente com infraestrutura blockchain, depois do SilentNet e sua interação com a rede Polygon na semana 2. A escolha específica da TON, popular no ecossistema de língua russa e fortemente integrada ao Telegram, é consistente com a origem provável dessa família.

O achado mais relevante para a série como um todo, porém, está no IP russo `217.26.28.234`. Esse endereço comunica com pelo menos 20 arquivos maliciosos adicionais, majoritariamente executáveis PE, todos seguindo o mesmo padrão de prefixo de hash com múltiplos zeros à esquerda já observado nos clusters de ArkeiStealer (semana 1), do dropper de CVE-2017-11882 e do script compartilhado do OverlordRAT (ambos desta mesma semana 3). Essa é a quarta vez que esse padrão específico de nomenclatura aparece associado a um cluster de infraestrutura compartilhada nesta série, o que já descarta a hipótese de coincidência ou artefato isolado de exportação levantada no relatório do OverlordRAT, e sugere fortemente que existe um conjunto de amostras, uma fonte de dados ou uma convenção de ferramenta específica por trás desse padrão, ainda não identificada. Fica como linha de investigação prioritária para a próxima rodada desta série.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `a0c5ebaa47f0cf3d8cd695d66b8c5e5561afd30da1b2f4d73f3736dca35efba7` |
| MD5 | `b4a65477542b3799b10940edaca3067e` |
| Nome do arquivo | `loader.exe` |
| Tamanho | 3.755.008 bytes |
| Primeira submissão | 25/07/2026 10:59:03 UTC |
| Detecção | 11 vendors |
| Regras YARA associadas | 61 |

---

## 3. Bundled Files e Dropped Files (2, mesmo conjunto)

| SHA256 | Tipo | Detecção |
|---|---|---|
| `7ae489b1c4f9d9036cdad55dbe7f408bcad8991713bca67f85ab7940515d5e1d` | PE EXE | Positiva |
| `153f9b0c4075f997b9cd4c86cc6a094c12a092b3daca28f4f6f3d34e2aacbdec` | Não informado | Sem atributos no export |

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (4)

| Domínio | Detecção | Observações |
|---|---|---|
| `sa1atik.cn` | Positiva | Typosquat direto do nome da família. Domínio de C2. |
| `tonapi.io` | Positiva | API da blockchain TON, uso malicioso confirmado pela detecção. |
| `ton.access.orbs.network` | Nenhuma | Segundo endpoint de acesso à rede TON. |
| `cloudflare-dns.com` | Nenhuma | Resolver DNS público, provável checagem de conectividade. |

### 4.2 IP de C2: 217.26.28.234 (Rússia)

| Métrica | Valor |
|---|---|
| Arquivos maliciosos comunicando com o IP | Ao menos 20 (17 PE EXE, 3 ZIP) |
| Certificado SSL histórico | 1 |
| Registro de WHOIS histórico | 2 |

Os hashes dos arquivos que comunicam com esse IP seguem o mesmo padrão de zeros à esquerda já documentado três vezes antes nesta série. A recorrência descarta coincidência isolada e eleva esse padrão a hipótese de pesquisa prioritária.

### 4.3 Segundo IP com detecção positiva

| IP | País | Observações |
|---|---|---|
| `2.59.219.233` | CH | Também contatado por um segundo arquivo malicioso no mesmo grafo, com registro de WHOIS histórico associado. |

### 4.4 Demais IPs contatados (14)

Faixas Cloudflare e Fastly sem detecção, prováveis dependências legítimas de resolução DNS e CDN.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Credentials from Password Stores | T1555 | Comportamento central e documentado da família SalatStealer. |
| Financial Theft | T1657 | Interação direta com endpoints de API da blockchain TON, segundo caso desta série após SilentNet (semana 2). |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o domínio de C2 typosquat. |
| Web Service | T1102 | Reaproveitamento confirmado do IP russo por ao menos 20 arquivos maliciosos adicionais. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): a0c5ebaa47f0cf3d8cd695d66b8c5e5561afd30da1b2f4d73f3736dca35efba7
SHA256 (PE bundled/dropped com detecção): 7ae489b1c4f9d9036cdad55dbe7f408bcad8991713bca67f85ab7940515d5e1d

Domínio de C2: sa1atik.cn
IP de C2 principal: 217.26.28.234
IP secundário: 2.59.219.233

Endpoints TON contatados (uso malicioso confirmado):
tonapi.io
ton.access.orbs.network
```

---

## 7. Recomendações

1. Bloquear o domínio `sa1atik.cn` e o IP `217.26.28.234` nos controles de perímetro.
2. Monitorar chamadas para os endpoints da rede TON a partir de processos não relacionados a carteiras ou clientes Telegram legítimos conhecidos no ambiente.
3. Abrir prioridade de investigação dedicada ao padrão de hash com zeros à esquerda, já recorrente em quatro clusters distintos desta série (ArkeiStealer, dropper CVE-2017-11882, script do OverlordRAT e agora SalatStealer), possivelmente indicando uma fonte, ferramenta ou dataset comum ainda não identificado.
4. Consultar diretamente no VT Graph o certificado SSL e os registros de WHOIS histórico do IP russo, para reconstruir a linha do tempo de uso dessa infraestrutura.
5. Considerar o tráfego para `cloudflare-dns.com` e as faixas de CDN legítima como ruído esperado, sem necessidade de bloqueio.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura SalatStealer).
Correlação cruzada com os relatórios 06_2026-07_arkeistealer (semana 1), 04_2026-07_cve-2017-11882-xlam-dropper e 07_2026-07_overlordrat (ambos semana 3) desta mesma série.
