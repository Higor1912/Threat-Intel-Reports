# Threat Intelligence Report: STRRAT

**ID:** week-05/04_2026-08_strrat
**Data:** 06/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como STRRAT via assinatura no MalwareBazaar, com 9 detecções entre vendors. O nome do arquivo, `Request For Quotation(RFQ).js`, segue o mesmo padrão de phishing corporativo temático de pedido de compra já recorrente nesta série.

Assim como já ocorreu com NanoCore (semana 1), SnakeKeylogger (semana 2) e parcialmente com StealeriumStealer (semana 4), esta amostra não tem nenhuma relação de rede direta própria no grafo. A única ligação é com uma coleção pública nomeada "STRRAT", que agrega uma quantidade maior de amostras da família catalogadas pela comunidade ao longo do tempo. Os indicadores a seguir devem ser tratados como conhecimento de família, não como IOCs confirmados desta amostra específica, seguindo o mesmo critério de transparência já aplicado nos casos anteriores.

Dito isso, o padrão da coleção é consistente e vale registro. Os 40 domínios listados são dominados por links do OneDrive (`1drv.com` e variações), hospedagem no Cloudflare Pages (`pages.dev`), CDN do Discord, e serviços de compartilhamento de arquivo como `filebin.net` e `bitbucket.org`. Esse é o padrão de distribuição documentado para STRRAT, que historicamente se apoia em anexos de malspam com links para payloads hospedados em serviços de nuvem gratuitos, evitando domínios próprios que possam ser bloqueados rapidamente. Um domínio de apostas, `administradores.bet`, também aparece na lista, repetindo o padrão de infraestrutura temática de apostas já visto em QuasarRAT (semana 1) e Gh0stRAT (semana 2).

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | JavaScript |
| SHA256 | `1162b0a85a471b942f594b6707c79652b49d0d349e4aca2e0779c42577291ec3` |
| MD5 | `7e1e26dadc9e0ec86cf6582f74d81cff` |
| Nome do arquivo | `Request For Quotation(RFQ).js` |
| Tamanho | 849.496 bytes |
| Primeira submissão | 06/08/2026 14:35:36 UTC |
| Detecção | 9 vendors |

---

## 3. Nota Metodológica sobre a Origem dos Dados de Rede

Esta amostra não possui nenhum domínio, IP, URL ou dropped file registrado diretamente no grafo. A única relação existente é com a coleção pública "STRRAT" da comunidade VT. Todos os indicadores listados na seção 4 vêm dessa coleção agregada, não de comportamento confirmado desta amostra específica.

---

## 4. Infraestrutura Associada à Família (via coleção pública)

### 4.1 Abuso de armazenamento em nuvem

| Serviço | Exemplos | Detecção |
|---|---|---|
| OneDrive | `0prlnw.by.files.1drv.com`, `1erlnw.by.files.1drv.com`, `7oelia.bl.files.1drv.com`, `dtom1q.am.files.1drv.com` | Majoritariamente positiva |
| Cloudflare Pages | `agrouphostning.pages.dev`, `excxcuteurl.pages.dev`, `fileshaaringdocumseign.pages.dev` | Positiva |
| Discord CDN | `cdn.discordapp.com` | Nenhuma |
| Bitbucket | `bitbucket.org` | Nenhuma |
| Filebin | `filebin.net` | Positiva |
| Mailjet (encurtador) | `03s5q.mjt.lu` | Positiva |

### 4.2 Domínio temático de apostas

| Domínio | Detecção |
|---|---|
| `administradores.bet` | Positiva |

Terceira ocorrência nesta série de infraestrutura com tema de apostas associada a um RAT, depois de QuasarRAT (semana 1) e Gh0stRAT (semana 2).

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Tema de isca de pedido de compra corporativo. |
| Web Service | T1102 | Padrão documentado de abuso de OneDrive e Cloudflare Pages para hospedagem de payload. |
| User Execution: Malicious File | T1204.002 | Entrega via anexo JavaScript malspam. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra analisada): 1162b0a85a471b942f594b6707c79652b49d0d349e4aca2e0779c42577291ec3

Indicadores de família (via coleção pública, não confirmados para esta amostra):
administradores.bet
filebin.net
excxcuteurl.pages.dev
```

---

## 7. Recomendações

1. Tratar os indicadores da seção 4 como regras de hunting genéricas para a família, não como bloqueio direto vinculado a esta amostra específica.
2. Monitorar downloads de arquivos executáveis ou script a partir de links do OneDrive e Cloudflare Pages recebidos por email, padrão de entrega documentado para STRRAT.
3. Sinalizar anexos JavaScript com tema de RFQ ou pedido de compra como indicador comportamental de triagem, tema recorrente nesta série.
4. Caso esta amostra apareça em ambiente monitorado, priorizar análise estática do conteúdo do JavaScript para identificar o link de download real, já que o grafo não trouxe esse dado diretamente.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura STRRAT).
Coleção pública do VT Graph: "STRRAT".
