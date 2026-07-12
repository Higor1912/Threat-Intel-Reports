# Threat Intelligence Report: QuasarRAT

**ID:** 08_2026-07_quasarrat
**Data:** 11/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como QuasarRAT via assinatura no MalwareBazaar, com 15 detecções entre vendors e 12 regras YARA associadas. O grafo revela uma cadeia de comando e controle construída sobre dois pilares que já apareceram separadamente em investigações anteriores desta coleção, mas aqui combinados na mesma amostra.

O primeiro pilar é a infraestrutura de domínio direta. O executável contata `kencangsm188.top` e `paptogel.net`, ambos usando o mesmo subdomínio `bdm.` como convenção de painel, e com nomes que remetem a plataformas de apostas e loteria online indonésias, tema recorrente em campanhas de phishing e malvertising na região. O primeiro domínio já tem detecção positiva, e o segundo é contatado por outros dois arquivos maliciosos distintos no mesmo grafo, confirmando reaproveitamento da infraestrutura entre campanhas.

O segundo pilar é mais sutil e tecnicamente relevante. O executável contata o IP `149.154.167.99`, que pertence à faixa oficial de servidores do Telegram, além do domínio `telegram.me` e de `steamcommunity.com`, este último também com detecção positiva. Essa combinação é característica da técnica de dead drop resolver, na qual o malware consulta uma página pública, como um perfil do Steam ou um canal do Telegram, para obter dinamicamente o endereço real do servidor de comando e controle, dificultando o bloqueio por IP fixo. O mesmo IP do Telegram aparece contatado por outros 11 arquivos maliciosos distintos neste grafo, o que sugere que essa técnica é usada de forma consistente por diferentes builds gerados a partir do mesmo builder ou operador.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074` |
| MD5 | `270193694f668c8717d9d0dfebd04312` |
| Tamanho | 1.657.584 bytes |
| Primeira submissão | 11/07/2026 00:10:07 UTC |
| Detecção | 15 vendors |
| Regras YARA associadas | 12 |

---

## 3. Bundled Files e Recursos (19 + 1)

A grande maioria dos 19 bundled files são ícones e um recurso de imagem PNG, sem detecção individual, consistentes com a interface gráfica do cliente QuasarRAT. Um recurso XML embutido (`pe_resource_children`) também aparece sem detecção, provável arquivo de configuração ou manifesto da aplicação.

---

## 4. Execution Parent e Dropped Files

O grafo lista o próprio hash da amostra como execution parent e como um dos dropped files, padrão comum quando o VT Graph identifica o binário se autoexecutando ou se recriando em disco. Entre os 6 dropped files, 5 não trouxeram atributos no export atual e precisam de checagem manual direta no VT Graph.

---

## 5. Infraestrutura de Rede

### 5.1 Domínios contatados (9)

| Domínio | Detecção | Observações |
|---|---|---|
| `kencangsm188.top` | Positiva | Domínio temático de apostas online, provável C2 direto. |
| `bdm.kencangsm188.top` | Positiva | Subdomínio de painel, mesmo padrão `bdm.` do domínio seguinte. |
| `paptogel.net` | Nenhuma | Contatado por outros 2 arquivos maliciosos no mesmo grafo, infraestrutura reaproveitada. |
| `bdm.paptogel.net` | Nenhuma | Mesmo padrão de subdomínio `bdm.` |
| `steamcommunity.com` | Positiva | Provável uso como dead drop resolver, técnica detalhada na seção 5.3. |
| `telegram.me` | Nenhuma | Mesmo papel de dead drop resolver, associado ao IP oficial do Telegram contatado diretamente. |
| `assets.adobedtm.com` | Nenhuma | Serviço legítimo da Adobe (tag management), provável ruído. |
| `i.lencr.org`, `x1.i.lencr.org` | Nenhuma | Infraestrutura da Let's Encrypt, validação de certificado. |

### 5.2 IPs contatados (11)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `149.154.167.99` | NL | Positiva | Faixa oficial de servidores do Telegram. Contatado por outros 11 arquivos maliciosos neste grafo. |
| `2.22.96.50` | GB | Positiva | Faixa Akamai. Também contatado por outro arquivo malicioso no mesmo grafo. |
| `104.21.11.137`, `172.67.166.35`, `172.67.195.151` | ZZ | Nenhuma | Faixa Cloudflare, provável proxy reverso dos domínios de apostas. |
| `104.21.41.228` | ZZ | Nenhuma | Mesma faixa Cloudflare. |
| `184.25.193.61`, `23.214.143.222` | GB | Nenhuma | Faixa Akamai. |
| `184.30.157.106`, `23.51.74.103` | NL | Nenhuma | Faixa Akamai. |
| `23.64.158.119` | US | Nenhuma | Faixa Akamai. |

### 5.3 Técnica de Dead Drop Resolver

A combinação de `steamcommunity.com` com detecção positiva e o contato direto ao IP oficial do Telegram é o achado tecnicamente mais relevante desta investigação. Essa técnica consiste em hospedar o endereço real do servidor de comando e controle em um campo de texto público, como a biografia de um perfil do Steam ou a descrição de um canal do Telegram, permitindo ao operador trocar a infraestrutura de C2 sem precisar recompilar o malware. O fato de o mesmo IP do Telegram aparecer em 12 arquivos distintos deste grafo (contando a amostra atual) reforça que essa técnica está associada a um builder ou operador que reutiliza o mesmo mecanismo de resolução em múltiplas campanhas.

### 5.4 URLs Contatadas

As 5 URLs listadas no grafo não trouxeram o texto completo no export atual, incluindo as 2 que apresentam detecção positiva. Recomenda se abrir cada nó diretamente no VT Graph para obter os valores exatos, já que provavelmente incluem o link específico do perfil Steam ou canal Telegram usado como resolver.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Dead Drop Resolver | T1102.001 | Uso combinado de Steam e Telegram para resolução dinâmica do endereço de comando e controle. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com os domínios de apostas via proxy Cloudflare. |
| Web Service | T1102 | Reaproveitamento de `paptogel.net` e do IP do Telegram entre múltiplos arquivos maliciosos do mesmo grafo. |
| User Execution: Malicious File | T1204.002 | Tema de apostas e loteria online como isca provável de distribuição. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): ed1565803c87371b03b576b6fcfb47ba3aeebdcfa07010f1c27ed9c91a70b074

Domínios de C2 confirmados:
kencangsm188.top
bdm.kencangsm188.top

Domínios de infraestrutura compartilhada:
paptogel.net
bdm.paptogel.net

Dead drop resolvers:
steamcommunity.com
telegram.me
IP oficial Telegram: 149.154.167.99
```

---

## 8. Recomendações

1. Bloquear os domínios `kencangsm188.top` e `bdm.kencangsm188.top` nos controles de perímetro.
2. Monitorar acessos a `steamcommunity.com` e `telegram.me` originados de processos não relacionados aos clientes oficiais dessas plataformas, já que o uso legítimo é comum e o bloqueio direto pode gerar impacto operacional.
3. Investigar isoladamente o domínio `paptogel.net`, dado seu reaproveitamento confirmado em outras amostras maliciosas do mesmo grafo.
4. Abrir diretamente no VT Graph as 5 URLs contatadas para obter o texto completo, já que provavelmente revelam o perfil ou canal específico usado como dead drop resolver.
5. Considerar o tráfego para `assets.adobedtm.com` e para a infraestrutura da Let's Encrypt como ruído esperado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura QuasarRAT).
