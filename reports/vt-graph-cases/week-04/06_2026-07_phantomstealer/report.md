# Threat Intelligence Report: PhantomStealer

**ID:** week-04/06_2026-07_phantomstealer
**Data:** 31/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como PhantomStealer via assinatura no MalwareBazaar, com 9 detecções entre vendors. O nome do arquivo, `FedEx Shipping Documents.js`, usa tema de notificação falsa de encomenda, mesmo padrão temático já visto no subdomínio `shipxpost.com` da investigação de RemusStealer na semana 2, embora sem relação de infraestrutura direta entre os dois casos, apenas repetição do mesmo tipo de isca social.

O comportamento de rede direto da amostra é majoritariamente ruído esperado: `icanhazip.com` para fingerprinting de IP, `time.windows.com` para sincronização de horário, `i.lencr.org` para validação de certificado Let's Encrypt, e `res.cloudinary.com`, serviço legítimo de hospedagem de imagens possivelmente abusado para entrega de recursos. O único domínio com detecção positiva contatado diretamente é `gimas.bg`, com tema búlgaro.

O achado relevante veio de um IP também hospedado na Bulgária, contatado pela amostra e que funciona como hub de distribuição documental. Esse endereço comunica com 20 arquivos maliciosos adicionais, mas com uma composição bem mais diversa do que os hubs vistos anteriormente nesta série: 10 executáveis PE, 4 arquivos RAR, 2 JavaScript, e um de cada entre PDF, DOCX, XLSX e RTF. Essa variedade de formatos de documento e arquivo compactado é consistente com uma infraestrutura de distribuição usada para múltiplas campanhas de phishing documental simultâneas, não uma cadeia dedicada a um único tipo de isca.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | Script (classificado como VBA pelo VT, arquivo com extensão .js) |
| SHA256 | `d65586d7420449da095e71b8a0951e2c8ee03895721faf5ab4804340841607ea` |
| MD5 | `0ce1ab2273f6438e9c840f6e8d900569` |
| Nome do arquivo | `FedEx Shipping Documents.js` |
| Tamanho | 26.014.282 bytes |
| Primeira submissão | 31/07/2026 05:49:28 UTC |
| Detecção | 9 vendors |
| Regras YARA associadas | 1 |

A classificação de tipo como VBA para um arquivo com extensão `.js` sugere conteúdo polimórfico ou embutido, possivelmente um script que encapsula ou invoca lógica de macro, o que reforça a suspeita de mecanismo de entrega não convencional para esse tipo de arquivo. Vale checagem manual do conteúdo real.

---

## 3. Dropped Files (2)

| SHA256 | Tipo | Detecção |
|---|---|---|
| `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` | JSON | Nenhuma |

O segundo dropped file listado é a própria amostra, indicando comportamento de autorreferência no grafo.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (6)

| Domínio | Detecção | Observações |
|---|---|---|
| `gimas.bg` | Positiva | Domínio búlgaro, provável ponto de distribuição ou C2. |
| `icanhazip.com` | Nenhuma | Fingerprinting de IP público. |
| `time.windows.com` | Nenhuma | Sincronização de horário, ruído esperado do sistema. |
| `i.lencr.org`, `x1.i.lencr.org` | Nenhuma | Validação de certificado Let's Encrypt. |
| `res.cloudinary.com` | Nenhuma | Serviço legítimo de hospedagem de imagens, possível abuso para entrega de recursos. |

### 4.2 IP de Distribuição Documental: 195.191.149.33 (Bulgária)

| Métrica | Valor |
|---|---|
| Arquivos comunicantes confirmados | 20, sendo 19 com detecção positiva |
| Composição | 10 PE EXE, 4 RAR, 2 JavaScript, 1 PDF, 1 DOCX, 1 XLSX, 1 RTF |
| Certificado SSL histórico | Presente |
| Registro de WHOIS histórico | Presente |

### 4.3 Demais IPs contatados (8)

Faixas Cloudflare e Fastly sem detecção, prováveis dependências legítimas de CDN associadas aos domínios de certificado e hospedagem de imagem.

### 4.4 URLs Contatadas (2)

Nenhuma das 2 URLs apresentou detecção, sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Tema de notificação falsa de encomenda (FedEx). |
| System Location Discovery | T1614 | Uso de `icanhazip.com` para fingerprinting. |
| Ingress Tool Transfer | T1105 | Infraestrutura documental compartilhada capaz de distribuir múltiplos formatos de payload. |
| Web Service | T1102 | Possível abuso de `res.cloudinary.com` para hospedagem de recursos. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): d65586d7420449da095e71b8a0951e2c8ee03895721faf5ab4804340841607ea

Domínio de distribuição: gimas.bg
IP de distribuição documental: 195.191.149.33
```

---

## 7. Recomendações

1. Bloquear o domínio `gimas.bg` e o IP `195.191.149.33` nos controles de perímetro.
2. Analisar o conteúdo real do arquivo `.js` principal para confirmar a classificação como VBA feita pelo VT, já que essa discrepância pode indicar técnica de entrega não convencional.
3. Orientar usuários sobre o tema recorrente de notificação falsa de encomenda como vetor de phishing, já visto também na investigação de RemusStealer (semana 2).
4. Investigar amostras representativas dos outros formatos de documento associados ao IP de distribuição (PDF, DOCX, XLSX, RTF) para mapear se pertencem à mesma campanha ou a operações paralelas usando a mesma infraestrutura.
5. Considerar o tráfego para `time.windows.com`, `i.lencr.org` e `res.cloudinary.com` como possível ruído, mas sem descartar completamente o Cloudinary como vetor de hospedagem até confirmação adicional.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura PhantomStealer).
