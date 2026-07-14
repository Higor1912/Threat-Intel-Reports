# Threat Intelligence Report: Snake Keylogger

**ID:** week-02/02_2026-07_snakekeylogger
**Data:** 13/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Snake Keylogger via assinatura no MalwareBazaar, com 8 detecções entre vendors e 19 regras YARA associadas, número alto de regras para um número relativamente baixo de detecções, o que sugere um sample bem estudado pela comunidade de pesquisa mesmo com evasão parcial de engines comerciais.

O nome do arquivo, `OSLO EAGLE.js`, segue o padrão comum de anexos maliciosos distribuídos por email corporativo, nomes que soam a documentos de remessa, licitação ou correspondência formal, usados para induzir a vítima a abrir um script que não aparenta ser um executável.

Diferente de todas as outras amostras desta coleção, este sample não apresenta nenhuma relação direta de rede no grafo: nenhum domínio, IP, URL ou dropped file contatado diretamente pelo JavaScript raiz. Toda a riqueza do grafo exportado (538 nós) vem de duas coleções públicas da comunidade VT dedicadas à família Snake Keylogger de forma ampla, não a este sample especificamente. Essas coleções reúnem 40 arquivos, mais de 100 domínios e 32 IPs associados à família como um todo, e servem aqui apenas como contexto de como a infraestrutura típica dessa família se comporta, não como IoCs verificados para esta amostra.

Vale o registro porque o padrão observado nessas coleções é consistente com o que já é documentado publicamente sobre o Snake Keylogger: uso extensivo de provedores de DNS dinâmico (`duckdns.org`, `ydns.eu`, `dns.army`) e da API do Telegram como canal de exfiltração, técnica que a família adota desde suas primeiras variantes documentadas.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | JavaScript |
| SHA256 | `889ae5f08236631f13d71877bf20232a09596b0c2b47132a7b3bb32bfba81d60` |
| MD5 | `bf43dbd5fae44aa9811d2d9412ddbcee` |
| Nome do arquivo | `OSLO EAGLE.js` |
| Tamanho | 2.283.506 bytes |
| Primeira submissão | 13/07/2026 15:24:29 UTC |
| Detecção | 8 vendors |
| Regras YARA associadas | 19 |

O tamanho do arquivo, acima de 2 MB para um script JavaScript, é incomum e sugere payload embutido em base64 dentro do próprio script, técnica comum para evitar a necessidade de um segundo download visível em ferramentas de monitoramento de rede.

---

## 3. Ausência de Relações Diretas de Rede

O nó raiz não apresenta nenhuma relação de `dropped_files`, `contacted_domains`, `contacted_ips`, `contacted_urls` ou `execution_parents` no export atual. A única relação direta são as duas coleções detalhadas na seção 4. Essa ausência pode indicar que a análise dinâmica no VT não completou a execução do script, ou que o comportamento de rede do Snake Keylogger nesta variante específica depende de um estágio de descriptografia em runtime não capturado pelo sandbox padrão.

---

## 4. Contexto via Coleções Públicas

### 4.1 Coleções associadas

| Nome | Domínios | Arquivos | URLs | IPs |
|---|---|---|---|---|
| Snake Keylogger Malware | 2 | 40 | 20 | Não listado |
| Snake Keylogger | 100 | 40 | 20 | 32 |

### 4.2 Padrões observados nas coleções (não específicos desta amostra)

**Domínios de DNS dinâmico:** `aborters.duckdns.org`, `accessgrant.ydns.eu`, `anotherarmy.dns.army`, entre outros, todos com detecção positiva. Esse é o padrão de infraestrutura mais recorrente entre as amostras da família reunidas na coleção.

**API do Telegram:** `api.telegram.org` aparece listado sem detecção individual, o que é esperado dado que se trata de um domínio legítimo. O uso desse endpoint por variantes da família é documentado publicamente como canal de exfiltração de credenciais e capturas de teclado, prática que dispensa infraestrutura própria de C2.

**IPs distribuídos geograficamente:** a lista de 32 IPs na coleção cobre Irã, Indonésia, Estados Unidos, França, Polônia, Turquia, Bulgária, Suécia e Noruega, sem concentração clara em um único provedor ou região, consistente com uma família amplamente distribuída e usada por múltiplos operadores independentes, não um ator único.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Nome de arquivo consistente com isca de correspondência corporativa. |
| Input Capture: Keylogging | T1056.001 | Comportamento central e confirmado da família Snake Keylogger. |
| Exfiltration Over Web Service | T1567 | Uso documentado da API do Telegram como canal de exfiltração pela família, observado nas coleções, não diretamente nesta amostra. |
| Dynamic Resolution | T1568 | Uso extensivo de provedores de DNS dinâmico nas amostras associadas à família, mesmo padrão. |

---

## 6. IoCs Consolidados

```
SHA256 (script JavaScript): 889ae5f08236631f13d71877bf20232a09596b0c2b47132a7b3bb32bfba81d60

Nenhum IoC de rede direto foi confirmado para esta amostra específica.
Os domínios e IPs listados na seção 4.2 pertencem à família de forma ampla,
reunidos por coleções da comunidade VT, e não foram individualmente
verificados como parte da cadeia de infecção desta amostra.
```

---

## 7. Recomendações

1. Reenviar a amostra para análise dinâmica completa no VT ou em sandbox próprio, já que o export atual não capturou nenhum comportamento de rede, possivelmente por limitação de tempo de execução do sandbox padrão.
2. Bloquear preventivamente o uso de subdomínios sob `duckdns.org`, `ydns.eu` e `dns.army` em ambientes corporativos que não dependam legitimamente desses serviços, dado o padrão recorrente entre variantes da família.
3. Monitorar tráfego de saída para `api.telegram.org` originado de processos de script (`wscript.exe`, `cscript.exe`) ou de aplicações que não sejam o cliente oficial do Telegram.
4. Orientar equipes sobre o risco de anexos `.js` disfarçados de documentos de remessa ou correspondência formal, vetor de entrada mais provável para esta amostra.
5. Tratar os indicadores da seção 4 como referência de padrão de família, não como lista de bloqueio direta, até validação individual de cada domínio ou IP.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Snake Keylogger).
Coleções públicas da comunidade VT associadas à família ("Snake Keylogger Malware" e "Snake Keylogger").
