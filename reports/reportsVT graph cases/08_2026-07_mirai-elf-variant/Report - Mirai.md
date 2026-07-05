
**ID:** 01_2026-07_mirai **Data:** 04/07/2026 **Analista:** Higor Silva **Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

Análise de amostra ELF da família Mirai, identificada via VirusTotal Graph, com 31 de 63 engines de antivírus detectando o binário como malicioso. A amostra contatou dois domínios (um legítimo, provavelmente usado como isca ou verificação de conectividade, e um malicioso com typosquatting do nome Cloudflare) e uma lista de 12 IPs majoritariamente composta por infraestrutura legítima de sistema, como resolvedores DNS públicos utilizados por variantes Mirai para checar acesso à internet antes de iniciar suas rotinas. Dentro desse conjunto, um bloco de endereços associados a um provedor britânico concentra as detecções positivas e representa o candidato mais provável a servidor de comando e controle. Também foram identificados 6 arquivos derivados (dropped files), consistentes com o comportamento de botnets Mirai que compilam variantes do payload para múltiplas arquiteturas de dispositivos IoT.

---

## 2. Indicador Primário

|Campo|Valor|
|---|---|
|Tipo|ELF|
|SHA256|`5608c97e85c8983e982423e326c9bb9d5e2149a207239782fd06a90de95b34c3`|
|Nome do arquivo|`5608c97e85c8983e982423e326c9bb9d5e2149a207239782fd06a90de95b34c3.elf`|
|Tamanho|870.55 kB|
|Primeira submissão|24/05/2026 06:31:31|
|Última submissão|24/05/2026 06:31:31|
|Detecções|31/63|

---

## 3. Infraestrutura de Rede

### 3.1 Domínios contatados (2)

|Domínio|Detecção|Observações|
|---|---|---|
|`api.snapcraft.io`|Não|Serviço legítimo do Canonical (Snap Store). Provavelmente contatado para checagem de conectividade ou como comportamento de disfarce.|
|`criminalcloudflare.online`|Sim|Domínio recém registrado que imita o nome Cloudflare. Padrão típico de typosquatting usado para mascarar infraestrutura de comando e controle. Candidato principal a C2.|

### 3.2 IPs contatados (12)

|IP|País|Detecção|Observações|
|---|---|---|---|
|`1.1.1.1`|ZZ|Não|Resolver público (Cloudflare DNS). Uso comum em Mirai para teste de conectividade.|
|`8.8.8.8`|US|Não|Resolver público (Google DNS). Mesmo padrão de checagem de conectividade.|
|`9.9.9.9`|ZZ|Sim|Resolver público (Quad9). Detecção provavelmente associada a reputação de uso abusivo, não a comportamento malicioso direto do endereço.|
|`208.67.222.222`|US|Sim|Resolver público (OpenDNS/Cisco). Mesmo padrão do item anterior.|
|`224.0.0.251`|ZZ|Não|Endereço multicast (mDNS). Tráfego de descoberta local, comum em dispositivos IoT comprometidos.|
|`176.65.139.191`|LU|Sim|Endereço fora do padrão de infraestrutura legítima observado no restante da lista. Merece verificação como possível ponto de distribuição secundário.|
|`185.125.188.54`|GB|Não|Parte de um bloco contíguo de IPs no Reino Unido.|
|`185.125.188.55`|GB|Não|Mesmo bloco.|
|`185.125.188.57`|GB|Sim|Mesmo bloco, com detecção positiva.|
|`185.125.188.58`|GB|Não|Mesmo bloco.|
|`185.125.188.59`|GB|Sim|Mesmo bloco, com detecção positiva.|
|`185.125.188.60`|GB|Sim|Mesmo bloco, com detecção positiva. Concentração de detecções nesse bloco sugere que seja a infraestrutura de comando e controle mais provável.|

---

## 4. Artefatos Relacionados

### 4.1 Dropped files (6)

|SHA256|Observações|
|---|---|
|`2811297bd8277c3319629670d02d06e9d33e117070d746fa1ce89c73d575e2a3`|A confirmar tipo e detecções via VT.|
|`41602099ac3b9c7e713fa0d7bf9c6d45ef23feabec6388df7bc24f5069f9b249`|A confirmar tipo e detecções via VT.|
|`a7e272834afa99cb6fc05b7ac01c2e989f7a43b568ec7033abb8edfb9313c90e`|A confirmar tipo e detecções via VT.|
|`d0a6fea56de3efc4b9786b11ca62622a363fa995674871db711d89dcea2333aa`|A confirmar tipo e detecções via VT.|
|`e375944c7c06dce7c2c9a587aa718287c5dfeaf5ca5194aa56764131592f4ca9`|A confirmar tipo e detecções via VT.|
|`ff1df8774e0be184e6141f3b863f42feed0ca2634f7d54502f7452a43b79f4a7`|A confirmar tipo e detecções via VT.|

O conjunto de 6 arquivos derivados é consistente com a prática do Mirai de disponibilizar binários compilados para arquiteturas diferentes (ARM, MIPS, x86, entre outras) a partir de um único servidor de distribuição, permitindo que o mesmo payload infecte uma variedade maior de dispositivos IoT.

### 4.2 Execution parents (1)

Confirmado no VT (1 execution parent), porém o hash correspondente não constava nos dados exportados do grafo. Recomenda se abrir o nó diretamente no VT Graph e copiar o valor pelo painel lateral.

---

## 5. Mapeamento MITRE ATT&CK

|Técnica|ID|Justificativa|
|---|---|---|
|Application Layer Protocol: DNS|T1071.004|Comunicação com domínio de C2 disfarçado como serviço legítimo (Cloudflare).|
|System Network Configuration Discovery|T1016|Consultas a múltiplos resolvedores DNS públicos, padrão de checagem de conectividade típico de Mirai antes de iniciar rotinas maliciosas.|
|Ingress Tool Transfer|T1105|Queda de 6 arquivos adicionais, compatível com download de binários compilados para arquiteturas distintas.|
|Network Denial of Service|T1498|Comportamento característico da família Mirai, cujo objetivo final majoritário é a formação de botnets para ataques DDoS.|

---

## 6. IoCs Consolidados

```
SHA256 (amostra primária): 5608c97e85c8983e982423e326c9bb9d5e2149a207239782fd06a90de95b34c3

Domínio C2: criminalcloudflare.online

IPs suspeitos:
176.65.139.191
185.125.188.57
185.125.188.59
185.125.188.60

Dropped files:
2811297bd8277c3319629670d02d06e9d33e117070d746fa1ce89c73d575e2a3
41602099ac3b9c7e713fa0d7bf9c6d45ef23feabec6388df7bc24f5069f9b249
a7e272834afa99cb6fc05b7ac01c2e989f7a43b568ec7033abb8edfb9313c90e
d0a6fea56de3efc4b9786b11ca62622a363fa995674871db711d89dcea2333aa
e375944c7c06dce7c2c9a587aa718287c5dfeaf5ca5194aa56764131592f4ca9
ff1df8774e0be184e6141f3b863f42feed0ca2634f7d54502f7452a43b79f4a7
```

---

## 7. Recomendações

1. Bloquear o domínio `criminalcloudflare.online` e o bloco de IPs `185.125.188.0/24` nos controles de perímetro.
2. Verificar a presença dos hashes listados na seção 4.1 no ambiente monitorado.
3. Investigar o endereço `176.65.139.191` isoladamente, já que destoa do restante da infraestrutura observada.
4. Confirmar o hash do execution parent diretamente no VT Graph, pois não estava disponível na exportação.
5. Considerar os resolvedores DNS públicos (itens sem detecção na seção 3.2) como ruído esperado do comportamento do malware, sem necessidade de bloqueio.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).