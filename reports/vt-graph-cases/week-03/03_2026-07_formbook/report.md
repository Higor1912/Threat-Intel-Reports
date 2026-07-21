# Threat Intelligence Report: Formbook

**ID:** week-03/03_2026-07_formbook
**Data:** 21/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Formbook via assinatura no MalwareBazaar, com 14 detecções entre vendors e 24 regras YARA associadas, o segundo maior número de regras desta série até agora. O nome do arquivo, `Order {RQF} Specification and Confirmation hNxy5bhw5mo919a.exe`, segue o padrão clássico de phishing corporativo temático de pedido de compra, isca recorrente para essa família desde que ela se consolidou como um dos infostealers mais vendidos no modelo malware as a service.

O achado mais relevante do grafo confirma exatamente essa natureza comercial. Um ícone bundled ao executável principal aparece como recurso compartilhado (`pe_resource_parents`) por 100 arquivos PE distintos, dos quais 85 já carregam detecção positiva própria. Um desses 100 arquivos, por sua vez, funciona como execution parent de mais 98 arquivos adicionais, formando uma segunda camada de reaproveitamento. Esse padrão em cascata, um recurso visual idêntico compartilhado por dezenas de amostras que depois se ramificam em ainda mais amostras, é a assinatura esperada de um builder comercial, onde múltiplos clientes geram binários diferentes a partir do mesmo template, muitas vezes sem trocar o ícone padrão da ferramenta.

No lado de rede direta, a amostra contata o domínio `www.blog-tk.online`, já com detecção positiva, como provável ponto de C2. Também contata um bloco de IPs na faixa `150.171.109.0/24` e `150.171.110.0/24`, associada a servidores de saída de email da Microsoft. Esse é o terceiro caso nesta série a mostrar contato com esse bloco específico, depois de ScarfaceStealer e SilentNet na semana anterior, o que já justifica tratar essa faixa como um padrão de reputação recorrente a ser monitorado de perto nas próximas investigações, independente de confirmação definitiva sobre a causa exata do compartilhamento.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `053b117e9ed3d97ed109590d414e1db9321475564e8ecd120221a56610b05c0c` |
| MD5 | `088d432df4ccadb352081564a4f4518b` |
| Nome do arquivo | `Order {RQF} Specification and Confirmation hNxy5bhw5mo919a.exe` |
| Tamanho | 1.152.512 bytes |
| Primeira submissão | 21/07/2026 11:36:03 UTC |
| Detecção | 14 vendors |
| Regras YARA associadas | 24 |

---

## 3. Ícone Compartilhado: Assinatura de Builder Comercial

| Indicador | Detalhe |
|---|---|
| SHA256 do ícone | `028f6dbdd69f43e0ae84546180447d20b41b0eb3c0a914fbb434622435da9753` |
| Arquivos que compartilham esse recurso | 100 executáveis PE distintos |
| Com detecção positiva própria | 85 de 100 |
| Segunda camada de reaproveitamento | Um desses 100 arquivos é execution parent de mais 98 arquivos adicionais |

Esse padrão não é incomum para Formbook especificamente, dado seu histórico documentado como produto comercial vendido em fóruns underground. Clientes diferentes compram acesso ao builder e geram amostras próprias, mas muitos não personalizam todos os recursos visuais do executável final, o que deixa esse tipo de rastro compartilhado entre campanhas de operadores completamente diferentes entre si.

---

## 4. Dropped Files e Demais Bundled Files

| SHA256 | Tipo | Observações |
|---|---|---|
| `7c207d29e8efc73141c4bdd33c763c4cd0286bd8c63e814e7fdec8c4129b7e51` | Texto | Único dropped file, sem detecção. |

Os outros 5 bundled files, além do ícone já detalhado, não trouxeram atributos no export atual.

---

## 5. Infraestrutura de Rede

### 5.1 Domínios contatados (2)

| Domínio | Detecção | Observações |
|---|---|---|
| `www.blog-tk.online` | Positiva | Provável domínio de C2. |
| `nexusrules.officeapps.live.com` | Nenhuma | Serviço legítimo da Microsoft, ruído esperado. |

### 5.2 IPs contatados (7)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `150.171.109.150` | US | Positiva | Faixa de saída de email da Microsoft, mesmo bloco visto em ScarfaceStealer e SilentNet (semana 2). |
| `150.171.109.74` | US | Positiva | Mesmo bloco. |
| `150.171.109.113`, `150.171.109.178`, `150.171.110.6` | US | Nenhuma | Mesmo bloco, sem detecção individual. |
| `13.107.226.70`, `13.107.253.70` | US | Nenhuma | Faixa Microsoft, ruído esperado. |

### 5.3 Coleções Associadas

Duas coleções públicas confirmam a atribuição: "Formbook Malware" e "FormBook", sem expansão adicional de indicadores no export atual.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Nome de arquivo temático de pedido de compra corporativo. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o domínio de C2. |
| Masquerading | T1036 | Reaproveitamento de ícone padrão de builder entre 100 amostras distintas, indicativo de origem comercial comum. |
| Credentials from Password Stores | T1555 | Comportamento central e documentado da família Formbook. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): 053b117e9ed3d97ed109590d414e1db9321475564e8ecd120221a56610b05c0c
SHA256 (ícone compartilhado por 100 amostras): 028f6dbdd69f43e0ae84546180447d20b41b0eb3c0a914fbb434622435da9753

Domínio de C2: www.blog-tk.online

Bloco de IPs recorrente nesta série (terceira ocorrência):
150.171.109.74
150.171.109.150
```

---

## 8. Recomendações

1. Bloquear o domínio `www.blog-tk.online` nos controles de perímetro.
2. Priorizar o ícone `028f6dbd...` como indicador de hunting de alto valor para identificar outras amostras do mesmo builder, dado seu reaproveitamento confirmado em 100 arquivos distintos.
3. Investigar uma amostra representativa dos 98 arquivos derivados do segundo nível de reaproveitamento para confirmar se pertencem à mesma campanha ou a operadores completamente diferentes usando o mesmo builder comercial.
4. Consolidar o padrão do bloco `150.171.109.0/24` observado pela terceira vez nesta série como item permanente de hunting, já que a recorrência em três famílias diferentes ao longo de duas semanas ultrapassa o que seria razoável atribuir à coincidência.
5. Orientar equipes de compras e financeiro sobre o tema recorrente de phishing baseado em pedidos e confirmações de compra, já visto em variações ao longo desta série.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Formbook).
