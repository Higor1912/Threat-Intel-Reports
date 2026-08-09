# Threat Intelligence Report: ACRStealer

**ID:** week-05/08_2026-08_acrstealer
**Data:** 08/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como ACRStealer via assinatura no MalwareBazaar, com 12 detecções entre vendors e 4 regras YARA associadas. O nome do arquivo, `bhatta.exe`, é um sobrenome comum no Nepal e na Índia, possível indício de isca ou origem regional específica, embora sem confirmação adicional no grafo.

O domínio de C2 é `caucasianjingling.cc`, com um subdomínio adicional `sso.caucasianjingling.cc` que sugere uma página de login falsa ou painel disfarçado de single sign-on, técnica comum para dar aparência legítima a um portal de coleta de credenciais. Nenhum dos dois teve resolução ou histórico adicional capturado neste export, mas ambos já carregam detecção positiva.

O achado que conecta esta investigação ao restante da série é o IP `150.171.110.210`, parte do bloco de servidores de saída de email da Microsoft já documentado nesta série desde ScarfaceStealer (semana 2). Esta é a quinta aparição confirmada desse bloco específico, depois de ScarfaceStealer, SilentNet, Formbook e Stealc, consolidando de vez esse padrão como item permanente de hunting para toda a série.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13` |
| MD5 | `03ec40f20de00f9a88abdbeb9aeaee23` |
| Nome do arquivo | `bhatta.exe` |
| Tamanho | 8.388.608 bytes |
| Primeira submissão | 08/08/2026 18:53:41 UTC |
| Detecção | 12 vendors |
| Regras YARA associadas | 4 |

---

## 3. Dropped Files, Bundled Files e Recurso PE

| SHA256 | Tipo | Detecção |
|---|---|---|
| `98e4f904f7de1644e519d09371b8afcbbf40ff3bd56d76ce4df48479a4ab884b` | PE EXE | Positiva |
| `0d0ee0e732175d953ee79f1b9b268086f79a98f52e6765d6c1242d714cc2c0c9` | Não informado | Sem atributos no export |
| `68d1fe908b1a7d43e292d6d5f0d89f2cba1cec5a232619d039a7bb2dfe3a6546` | CAB | Nenhuma, recurso PE embutido |

Os 20 bundled files são majoritariamente texto, XML e um arquivo AVI, todos sem detecção, consistentes com recursos de interface de um instalador ou aplicativo de fachada.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (6)

| Domínio | Detecção | Observações |
|---|---|---|
| `caucasianjingling.cc` | Positiva | Domínio de C2 principal. |
| `sso.caucasianjingling.cc` | Positiva | Subdomínio temático de single sign-on, possível painel de coleta de credenciais disfarçado. |
| `a1672.dscr.akamai.net`, `dns.google`, `microsoft.com`, `time.windows.com` | Nenhuma | Ruído esperado de telemetria e conectividade. |

### 4.2 IPs contatados (11)

| IP | Detecção | Observações |
|---|---|---|
| `150.171.110.210` | Positiva | Bloco de saída de email da Microsoft, quinta aparição confirmada nesta série. |
| `150.171.109.200` | Nenhuma | Mesmo bloco, sem detecção individual. |
| Demais 9 IPs | Nenhuma | Faixas Cloudflare, Akamai e resolvedores públicos, ruído esperado. |

### 4.3 URLs Contatadas (5)

4 das 5 URLs apresentam detecção positiva, sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Credentials from Password Stores | T1555 | Comportamento central e documentado da família ACRStealer. |
| Phishing | T1566 | Subdomínio temático de single sign-on, possível painel de credenciais disfarçado. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o domínio de C2. |
| Web Service | T1102 | Reaproveitamento confirmado do bloco Microsoft já documentado cinco vezes nesta série. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13

Domínio de C2: caucasianjingling.cc
Subdomínio: sso.caucasianjingling.cc
IP do bloco Microsoft (quinta aparição): 150.171.110.210
```

---

## 7. Recomendações

1. Bloquear `caucasianjingling.cc` e seu subdomínio `sso.caucasianjingling.cc` nos controles de perímetro.
2. Consolidar definitivamente o bloco `150.171.109.0/24` e `150.171.110.0/24` como item permanente de hunting em toda a base de relatórios desta série, dado o volume de recorrência já confirmado.
3. Verificar a presença do PE EXE com detecção positiva entre os dropped files no ambiente monitorado.
4. Abrir diretamente no VT Graph as 4 URLs com detecção positiva para obter o texto completo, já que provavelmente revelam o endpoint específico do painel de credenciais.
5. Considerar o tráfego para Google, Microsoft e Akamai como ruído esperado, sem necessidade de bloqueio isolado.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura ACRStealer).
Correlação cruzada com os relatórios 04_2026-07_scarfacestealer (semana 2), 08_2026-07_silentnet (semana 2), 03_2026-07_formbook (semana 3) e 07_2026-08_stealc (semana 4) desta mesma série.
