# Threat Intelligence Report: Phorpiex

**ID:** week-03/02_2026-07_phorpiex
**Data:** 20/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Phorpiex via assinatura no MalwareBazaar, com 14 detecções entre vendors e 8 regras YARA associadas. Phorpiex, também conhecido como Trik, é um worm e botnet de spam ativo desde meados dos anos 2010, historicamente associado a campanhas de sextorsão em massa e distribuição secundária de outras famílias, incluindo ransomware e stealers, através de uma rede de bots que envia email diretamente para servidores de destino.

O arquivo tem apenas 18 KB, um dos menores desta série até agora, consistente com a natureza enxuta desse worm, que prioriza velocidade de propagação e envio de spam sobre funcionalidade complexa embutida. A infraestrutura de rede é onde a assinatura comportamental da família fica mais evidente. A amostra contata 204 domínios diretamente, e a esmagadora maioria corresponde a servidores de troca de email (MX) de provedores de webmail e ISPs ao redor do mundo: `126.com`, `163.com`, `aol.com`, `att.net`, `bellsouth.net`, `btinternet.com`, `yahoo.com.tw`, `seznam.cz`, entre dezenas de outros. Esse é o comportamento clássico do Phorpiex, que se conecta diretamente aos servidores MX das vítimas para disparar spam em massa sem depender de um relay de terceiros, e é a confirmação mais direta e específica de família observada nesta série até agora, só pelo padrão de rede.

Dos 204 domínios contatados, 15 já carregam detecção positiva, incluindo grandes provedores como `yahoo.com.tw`, `yahoo.es` e `rocketmail.com`. Vale uma ressalva importante aqui: essa detecção não significa que esses provedores de email sejam maliciosos. Reflete reputação de abuso associada ao volume de spam direcionado a esses servidores específicos por essa e outras campanhas Phorpiex, não comprometimento da infraestrutura do provedor em si.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `29911dea1c2e80d6d21571038afeccad47535e841e03091824a0996e94631117` |
| MD5 | `b717c08d93438b18dcdbc13952e0ed33` |
| Nome do arquivo | `file` (nome genérico) |
| Tamanho | 18.432 bytes |
| Primeira submissão | 20/07/2026 12:09:48 UTC |
| Última submissão | 20/07/2026 12:39:21 UTC |
| Detecção | 14 vendors |
| Regras YARA associadas | 8 |

---

## 3. Execution Parent, Bundled Files e Dropped Files

| SHA256 | Tipo | Papel |
|---|---|---|
| `d7edbb3e6ef59d56861f4bd4e5be6fdf5a954c0fb745ef79289815832f4573c5` | PE EXE | Execution parent, com detecção positiva própria e sem relações adicionais detalhadas nesta rodada. |

Os 6 bundled files e os 4 dropped files trouxeram pouco detalhe no export atual, majoritariamente sem atributos ou classificados apenas como texto, sem detecção individual.

---

## 4. Infraestrutura de Rede: o Mecanismo de Spam em Massa

### 4.1 Domínios contatados (204 no total, amostra representativa)

| Categoria | Exemplos | Detecção |
|---|---|---|
| Webmail asiático | `126.com`, `163.com`, `daum.net` | Mista, 2 positivas |
| Webmail e ISPs norte-americanos | `aol.com`, `att.net`, `bellsouth.net`, `sbcglobal.com`, `rocketmail.com` | Mista, algumas positivas |
| Webmail europeu | `btinternet.com`, `alice.it`, `virgilio.it`, `seznam.cz`, `bluemail.ch` | Mista, algumas positivas |
| Infraestrutura corporativa de email | `aspmx.l.google.com`, `mail.protection.outlook.com` (subdomínios diversos) | Nenhuma |

Do total de 204 domínios, 15 apresentam detecção positiva, todos servidores de email de provedores legítimos afetados por reputação de abuso, não infraestrutura própria do operador.

### 4.2 IPs contatados (177 no total)

Do total, 27 apresentam detecção positiva, distribuídos entre Hong Kong, Cingapura, Coreia do Sul, Chile e outros países, consistentes com os servidores de email associados aos domínios da seção 4.1.

### 4.3 URLs Contatadas (5)

4 das 5 URLs têm detecção positiva, sem texto completo disponível no export atual.

### 4.4 Coleção Associada

O grafo confirma uma coleção pública nomeada diretamente "Phorpiex", reforçando a atribuição já obtida via MalwareBazaar.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Phishing: Spearphishing via Service / Mass Mailing | T1566 | Comportamento central da família, conexão direta com servidores MX para envio de spam em massa. |
| Application Layer Protocol: Mail Protocols | T1071.003 | Comunicação SMTP direta com 177 IPs de servidores de email. |
| Ingress Tool Transfer | T1105 | Distribuição secundária de outras famílias, comportamento historicamente documentado do Phorpiex como botnet de entrega. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 29911dea1c2e80d6d21571038afeccad47535e841e03091824a0996e94631117
SHA256 (execution parent): d7edbb3e6ef59d56861f4bd4e5be6fdf5a954c0fb745ef79289815832f4573c5

Domínios de email com detecção positiva (reputação de abuso):
126.com
daum.net
mta6.am0.yahoodns.net
rocketmail.com
sbcglobal.com
seznam.cz
yahoo.com.tw
yahoo.es
```

---

## 7. Recomendações

1. Monitorar conexões SMTP diretas originadas de hosts internos para servidores MX externos fora do fluxo normal do servidor de email corporativo, padrão comportamental mais eficaz para detectar Phorpiex do que bloqueio de domínio, já que os destinos são majoritariamente provedores legítimos.
2. Tratar a lista de domínios da seção 4.1 como referência de comportamento, não como lista de bloqueio, dado que bloquear provedores como Yahoo ou AOL inteiros geraria impacto operacional desproporcional.
3. Verificar se o host de origem apresenta outros sinais de comprometimento além deste binário, já que o papel histórico do Phorpiex como distribuidor secundário significa que sua presença pode indicar infecção adicional por outra família.
4. Abrir diretamente no VT Graph as URLs com detecção positiva para obter o texto completo, já que podem revelar o mecanismo exato de propagação ou o servidor de atualização do bot.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Phorpiex).
