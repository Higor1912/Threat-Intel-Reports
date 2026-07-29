# Threat Intelligence Report: StealeriumStealer

**ID:** week-04/04_2026-07_stealeriumstealer
**Data:** 29/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como StealeriumStealer via assinatura no MalwareBazaar, com 15 detecções entre vendors e 25 regras YARA associadas. Stealerium é um stealer de código aberto disponível publicamente, o que explica o volume alto de detecção mesmo sem infraestrutura de C2 dedicada e exclusiva, já que assinaturas genéricas cobrem qualquer build compilado a partir do mesmo código-fonte. O nome do arquivo, `MATCHACRACKED.exe`, segue o padrão já recorrente nesta série de distribuição via software ou jogo crackeado.

O comportamento de rede confirma exatamente o que é documentado publicamente sobre a família: exfiltração via webhook do Discord (`discordapp.com`) e checagem de IP público via `icanhazip.com`, sem domínio de C2 próprio e dedicado. O restante dos domínios contatados diretamente é infraestrutura de validação de certificado digital (Certum, Symantec), ruído esperado de qualquer executável assinado ou que verifica assinaturas.

Esta investigação também traz uma ressalva metodológica importante para futuras amostras que contatem infraestrutura do Discord. Os quatro IPs com detecção positiva contatados pela amostra pertencem à faixa compartilhada da Cloudflare usada pelo CDN do próprio Discord, não a um servidor dedicado. O histórico de resolução desses IPs traz uma mistura de domínios completamente não relacionados entre si, de aliases legítimos do Discord a domínios iranianos suspeitos e nomes aleatórios sob TLDs diversos, resultado esperado de um endereço IP compartilhado por milhares de propriedades diferentes atrás da mesma borda Cloudflare. Tratar esse histórico como evidência de campanha seria um erro de atribuição, e fica registrado aqui como critério de triagem para as próximas investigações que envolvam infraestrutura de Discord ou qualquer outro serviço fortemente compartilhado atrás de Cloudflare.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `6231e3ba7d5643ee173f92ef33d2dafa4bc2986954b16cd53195a3b87e3aa5a5` |
| MD5 | `6d141be8566a768dec036c4a6a173f6b` |
| Nome do arquivo | `MATCHACRACKED.exe` |
| Tamanho | 7.371.776 bytes |
| Primeira submissão | 29/07/2026 07:40:25 UTC |
| Detecção | 15 vendors |
| Regras YARA associadas | 25 |

---

## 3. Bundled Files e Dropped Files

Os 3 bundled files e os 5 dropped files não trouxeram atributos detalhados no export atual, à exceção de um arquivo de texto entre os dropados, sem detecção. Nenhum apresentou relações adicionais de rede na expansão realizada.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (7)

| Domínio | Detecção | Observações |
|---|---|---|
| `discordapp.com` | Nenhuma | Canal de exfiltração via webhook, comportamento documentado e esperado da família. |
| `icanhazip.com` | Nenhuma | Checagem de IP público, fingerprinting padrão antes da coleta de dados. |
| `ccsca2021.ocsp-certum.com`, `ocsp-certum.com`, `subca.ocsp-certum.com` | Nenhuma | Validação de certificado digital, ruído esperado. |
| `evcs-crl.ws.symantec.com`, `evcs-ocsp.ws.symantec.com` | Nenhuma | Mesma função, infraestrutura da Symantec. |

### 4.2 IPs contatados (10), com ressalva sobre atribuição

| IP | Detecção | Observações |
|---|---|---|
| `162.159.129.233`, `162.159.130.233`, `162.159.133.233`, `162.159.134.233` | Positiva | Faixa compartilhada da Cloudflare usada pelo CDN do Discord. Ver ressalva metodológica na seção 1 e 4.3. |
| `104.16.184.241`, `104.16.185.241` | Nenhuma | Mesma faixa Cloudflare/Discord. |
| `162.159.135.233` | Nenhuma | Mesma faixa. |
| `23.205.89.166`, `23.205.89.190` | Nenhuma | Faixa Akamai, provável infraestrutura de validação de certificado. |
| `8.8.8.8` | Nenhuma | Resolver público, checagem de conectividade. |

### 4.3 Nota sobre o Histórico de Resolução dos IPs Compartilhados

Os quatro IPs com detecção positiva têm, cada um, 20 domínios em seu histórico de resolução, mas a composição é heterogênea e sem tema comum: aliases legítimos do próprio Discord (`staging-cdn.discordapp.com`, `cdn.discordapp.com.cdn.cloudflare.net`) aparecem lado a lado com domínios iranianos (`mobile-imperial.ir`, `onlinernet.ir`), serviços de DNS dinâmico (`cloudns.org`) e nomes curtos sob TLDs diversos (`.top`, `.cc`, `.pro`, `.sbs`). Essa dispersão temática é o próprio indício de que o histórico reflete o compartilhamento do endereço IP entre milhares de domínios não relacionados atrás da mesma borda Cloudflare, não uma campanha específica associada a esta amostra.

### 4.4 URLs Contatadas (6)

Nenhuma das 6 URLs apresentou detecção, sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Exfiltration Over Web Service | T1567 | Uso de webhook do Discord para exfiltração, comportamento documentado da família. |
| System Location Discovery | T1614 | Checagem de IP público via `icanhazip.com`. |
| User Execution: Malicious File | T1204.002 | Nome de arquivo associado a software crackeado. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 6231e3ba7d5643ee173f92ef33d2dafa4bc2986954b16cd53195a3b87e3aa5a5
```

Nenhum IP ou domínio dedicado de C2 foi confirmado nesta investigação, consistente com o modelo de exfiltração via serviço de terceiros (Discord) característico da família.

---

## 7. Recomendações

1. Monitorar tráfego de saída para webhooks do Discord originado de processos não relacionados ao cliente oficial, já que esse é o canal de exfiltração real desta família, não um domínio dedicado passível de bloqueio direto.
2. Orientar usuários sobre o risco de software crackeado como vetor de entrada, tema recorrente nesta amostra e em outras já cobertas por esta série.
3. Não tratar o histórico de resolução dos IPs compartilhados da Cloudflare/Discord (seção 4.3) como IOC de campanha em relatórios futuros, aplicando o mesmo critério de triagem já usado para ruído de sandbox em amostras ELF.
4. Expandir manualmente os 3 bundled files e os 5 dropped files sem atributos no export atual diretamente no VT Graph, caso se torne necessário aprofundar esta investigação.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura StealeriumStealer).
