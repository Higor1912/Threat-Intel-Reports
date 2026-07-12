# Threat Intelligence Report: ArkeiStealer

**ID:** 06_2026-07_arkeistealer
**Data:** 09/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como ArkeiStealer via assinatura no MalwareBazaar, com 9 detecções entre vendors e 8 regras YARA associadas. O nome do arquivo, `KungFu_patched.exe`, sugere fortemente o vetor de entrega mais comum dessa família: distribuição disfarçada de software crackeado ou patches de jogos, prática recorrente em campanhas de malvertising que direcionam vítimas para sites de download não oficiais.

O executável principal contata um único IP diretamente, hospedado na Polônia, que se revela o achado mais relevante desta investigação. Esse endereço acumula 35 domínios em seu histórico de resolução DNS, formando dois grupos temáticos bem definidos. O primeiro imita o programa de cartões de crédito da rede de lojas Dillard's, nos Estados Unidos. O segundo se concentra em portais falsos de fatura eletrônica e aplicativos genéricos de gestão financeira, com nomes como `invoicereview.cc`, `techmoneyrank.cc` e `fatturazioneelettronicaonline.org`, vários deles já com detecção positiva. Esse padrão é característico de infraestrutura de phishing reaproveitada para atrair vítimas antes da entrega do stealer propriamente dito. O mesmo IP também comunica com outros 2 arquivos maliciosos distintos além da amostra atual, confirmando que se trata de infraestrutura compartilhada entre múltiplas campanhas, não exclusiva desta amostra.

Entre os 2 dropped files, um chama atenção por comportamento fora do padrão típico de um stealer. Trata se de um segundo executável PE, também com detecção positiva, que contata 40 endereços IP, dos quais cerca de 30 pertencem à faixa local `192.168.0.0/24`. Esse volume de endereços internos distintos sugere um módulo de reconhecimento de rede local, possivelmente voltado a mapear outros dispositivos na mesma rede da vítima antes de decidir sobre movimentação lateral ou coleta adicional de dados.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e` |
| MD5 | `b65213cc6c7631f409b0c3fb370aab58` |
| Nome do arquivo | `KungFu_patched.exe` |
| Tamanho | 4.444.160 bytes |
| Primeira submissão | 09/07/2026 19:11:28 UTC |
| Detecção | 9 vendors |
| Regras YARA associadas | 8 |

---

## 3. Dropped Files (2)

| SHA256 | Tipo | Detecção | Observações |
|---|---|---|---|
| `92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45` | PE EXE | Positiva | Módulo de reconhecimento de rede local, detalhado na seção 5. |
| `d04eaf2f4683ceb6f723773d1251994cc042dd4dbd8ff29db204a98500433c76` | Não informado | Nenhuma | Sem atributos adicionais no export. |

---

## 4. Infraestrutura de Rede do Executável Principal

### 4.1 IP contatado: 193.111.117.131 (Polônia)

Esse endereço concentra o valor analítico principal da investigação, tanto pelo histórico de resolução DNS quanto pelo reaproveitamento em outras campanhas.

**Histórico de resolução (35 domínios, destaques abaixo)**

| Domínio | Detecção | Tema |
|---|---|---|
| `travelbenefits.cc` | Positiva | Portal falso de benefícios de viagem |
| `www.techmoneyrank.cc` / `techmoneyrank.cc` | Positiva | Aplicativo falso de gestão financeira |
| `appsinvoising.cc` / `www.appsinvoising.cc` | Positiva | Portal falso de faturamento |
| `einvoising.cc` / `www.einvoising.cc` | Positiva | Portal falso de fatura eletrônica |
| `invoicereview.cc` | Positiva | Portal falso de revisão de faturas |
| `invoicesquickly.cc` | Positiva | Portal falso de faturamento rápido |
| `reviewinvoices.cc` / `www.reviewinvoices.cc` | Positiva | Mesmo tema de fatura falsa |
| `www.dillcard.com`, `www.dillards-card.com`, `dillards-card.com` | Nenhuma | Imitação do programa de cartão de crédito da rede Dillard's |
| `dillardapp.org`, `www.dillardapp.org` | Nenhuma | Mesmo tema, variante de aplicativo |
| `fatturazioneelettronicaonline.org` | Nenhuma | Portal falso de fatura eletrônica, tema italiano |
| `fitcarapp.org`, `destinyapp.org`, `milestoneapp.org`, `cerulanapp.org`, `reflexeapp.org`, `lnvoicetogo.org` | Nenhuma | Aplicativos genéricos sem tema financeiro claro, provável reciclagem de infraestrutura para outros iscas |

**Outros arquivos que comunicam com o mesmo IP**

| SHA256 | Tipo |
|---|---|
| `b2a3b67fb3ead7e3cf774ec6a3b09d0b9a2e99b273896e1fb7f5c38c564b8ab4` | PE EXE, detecção positiva |
| `fbf26aec78c95f02957c81338bc054cec2a2da75d80247cd7edf442b65c83a79` | PE EXE, detecção positiva |

O IP também possui registro de WHOIS histórico e certificado SSL histórico associados, cujos valores completos não vieram detalhados no export atual e ficam disponíveis para consulta direta no VT Graph.

### 4.2 URL contatada

O grafo lista uma URL contatada pelo executável principal, sem o texto completo disponível no export atual. Recomenda se abrir o nó diretamente no VT Graph para obter o valor exato.

---

## 5. Módulo de Reconhecimento de Rede Local

O segundo dropped file contata 40 endereços IP distintos. A composição chama atenção pela proporção de endereços internos.

| Faixa | Quantidade | Observações |
|---|---|---|
| `192.168.0.0/24` | 30 | Endereços de rede local distintos, padrão consistente com varredura ou descoberta de hosts na rede da vítima. |
| CDN legítima (Akamai, Fastly, Cloudflare) | 9 | Provável ruído de telemetria ou verificação de conectividade. |
| `13.107.4.50` (Microsoft, US) | 1 | Detecção positiva, possivelmente ligada a reputação de uso abusivo do endereço, não a comportamento malicioso direto do IP. |

O grande número de hosts internos distintos contatados por um único binário é um comportamento fora do padrão de um stealer convencional, que normalmente se limita a exfiltrar dados do próprio host infectado. Esse módulo merece investigação adicional para confirmar se a função é apenas descoberta passiva de rede ou se há tentativa ativa de movimentação lateral.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Nome de arquivo (`KungFu_patched.exe`) consistente com isca de software crackeado. |
| Credentials from Password Stores | T1555 | Comportamento característico da família ArkeiStealer, voltada a credenciais de navegador e carteiras de criptomoeda. |
| Network Service Discovery | T1046 | Volume elevado de IPs internos distintos contatados pelo módulo secundário, seção 5. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de comando e controle na Polônia. |
| Phishing | T1566 | Infraestrutura de domínios falsos de fatura e cartão de benefícios associada ao IP de C2, provável origem da cadeia de entrega. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): 4cca32f774fe33f96b8cca18dc5b24bf93abe684516f2722331f49f66d2b940e
SHA256 (módulo de reconhecimento de rede): 92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45
SHA256 (outros arquivos no mesmo C2):
b2a3b67fb3ead7e3cf774ec6a3b09d0b9a2e99b273896e1fb7f5c38c564b8ab4
fbf26aec78c95f02957c81338bc054cec2a2da75d80247cd7edf442b65c83a79

IP de comando e controle: 193.111.117.131

Domínios de phishing associados (detecção positiva):
travelbenefits.cc
techmoneyrank.cc
appsinvoising.cc
einvoising.cc
invoicereview.cc
invoicesquickly.cc
reviewinvoices.cc
```

---

## 8. Recomendações

1. Bloquear o IP `193.111.117.131` e todos os domínios listados na seção 4.1 nos controles de perímetro.
2. Verificar a presença do módulo de reconhecimento de rede (seção 5) em máquinas comprometidas, priorizando a checagem de tentativas de conexão a outros hosts na rede local.
3. Orientar usuários finais sobre o risco de sites de software crackeado como vetor de entrada, dado o nome do arquivo analisado.
4. Consultar diretamente no VT Graph o certificado SSL e o registro WHOIS histórico do IP de C2, para reconstruir eventual reaproveitamento de infraestrutura ao longo do tempo.
5. Considerar o tráfego para IPs de CDN legítima (Akamai, Fastly, Cloudflare) listado na seção 5 como ruído esperado, sem necessidade de bloqueio isolado.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura ArkeiStealer).
