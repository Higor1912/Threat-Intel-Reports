# Threat Intelligence Report: SalatStealer (segunda amostra desta série)

**ID:** week-05/05_2026-08_salatstealer-ii
**Data:** 06/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como SalatStealer via assinatura no MalwareBazaar, com 9 detecções entre vendors e 5 regras YARA associadas. Essa é a segunda vez que a família aparece nesta série, depois da investigação da semana 3, e mais uma vez o grafo trouxe o script PowerShell compartilhado (`96ad1146...`) que já conecta ValleyRAT, ScarfaceStealer, OverlordRAT e LxBaseRAT ao longo de quatro semanas anteriores.

Desta vez, porém, a expansão completa do script trouxe dados suficientes para fechar uma questão em aberto desde a investigação de OverlordRAT, na semana 3. O script contata simultaneamente os dois domínios quase idênticos que originaram toda essa linha de investigação, `cl-glcb907925.gcdn.co` e `cl-glcb907925.globalcdn.co`, além do bloco `208.89.72.0/24`, o mesmo já documentado como infraestrutura desse script no relatório de OverlordRAT. Mais importante, a lista de execution parents deste script confirma definitivamente a origem do padrão de hash com múltiplos zeros à esquerda que já havia aparecido em ArkeiStealer (semana 1), no dropper de CVE-2017-11882 (semana 3), no próprio OverlordRAT (semana 3) e na primeira amostra de SalatStealer (semana 3). Esse padrão pertence a este script especificamente, não é artefato de exportação nem coincidência espalhada por clusters diferentes, é a assinatura de nomenclatura de um único conjunto de amostras que passam por este mesmo componente.

As coleções públicas associadas ao script reforçam essa conclusão de forma direta. Ele aparece referenciado em dezenas de coleções sem relação temática alguma entre si, de "AKIRA RaaS" a "Threat Landscape Integrating LLM with Discord" a "Spearphishing Norway", confirmando que se trata de um componente genérico, provavelmente parte de um toolkit ou loader compartilhado, distribuído independentemente de qualquer família ou operador específico.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `dd17e871204619a3de34126e366221b64e684ec13e24dfc871698abe343acbff` |
| MD5 | `266f2cfe9aecf638c06b3efcbdd07756` |
| Nome do arquivo | `Fix.exe` |
| Tamanho | 2.097.152 bytes |
| Primeira submissão | 06/08/2026 19:01:06 UTC |
| Detecção | 9 vendors |
| Regras YARA associadas | 5 |

---

## 3. O Script Compartilhado: Questão Resolvida

| SHA256 | `96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7` |
|---|---|
| Tipo | PowerShell |
| Aparições anteriores nesta série | ValleyRAT (semana 1, infraestrutura), ScarfaceStealer (semana 2, infraestrutura), OverlordRAT (semana 3, expansão completa), LxBaseRAT (semana 5, dropped file), SalatStealer primeira amostra (semana 3, IP russo com mesmo padrão de hash) |

**Domínios contatados por este script (confirmação, 20 no total)**

| Domínio | Detecção |
|---|---|
| `cl-glcb907925.gcdn.co` | Positiva |
| `cl-glcb907925.globalcdn.co` | Nenhuma |
| Demais domínios | Infraestrutura Microsoft/Akamai e entradas de resolução reversa, ruído esperado |

**IPs contatados por este script (confirmação, 20 no total)**

Bloco `208.89.72.0/24`, com 5 dos 15 endereços amostrados carregando detecção positiva, idêntico ao já documentado no relatório de OverlordRAT.

**Execution parents (20 exibidos, número real maior)**

Todos seguem o padrão de prefixo com múltiplos zeros à esquerda (`0000...`), cobrindo PE EXE, PowerShell, MSI, ZIP, LNK e JavaScript. Com esta quinta confirmação do mesmo padrão associado ao mesmo script específico, fica estabelecido que essa nomenclatura pertence a este componente, não a um artefato disperso de exportação do VT Graph.

**Coleções associadas (amostra de 15, sem tema comum entre si)**

`AKIRA RaaS`, `Threat Landscape Integrating LLM with Discord`, `NDA.gov.uk`, `Spearphishing Norway`, `Free Espionage`, `Indeed force download`, `144.172.123.254 Malicious Scanning`, entre outras. A dispersão total de temas confirma que este script é um componente genérico referenciado por dezenas de investigações não relacionadas entre si na comunidade VT, consistente com origem em toolkit ou loader compartilhado.

---

## 4. Infraestrutura de Rede Direta da Amostra Principal

| Indicador | Detecção | Observações |
|---|---|---|
| `dns.google`, `time.windows.com` | Nenhuma | Ruído esperado. |
| `193.221.200.26` | Positiva | Rússia, provável C2 direto. |
| `8.8.4.4` | Positiva | Resolver público Google, provável ruído de reputação. |
| 1 URL contatada | Positiva | Sem texto completo disponível no export atual. |

---

## 5. Dropped Files (40)

Composição majoritariamente arquivos de texto e CSV sem detecção (consistentes com dados coletados pelo stealer), um PE EXE com detecção positiva, e o próprio script PowerShell compartilhado detalhado na seção 3.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Web Service | T1102 | Confirmação definitiva do papel do script compartilhado como elo entre cinco investigações desta série. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de C2 russo. |
| Credentials from Password Stores | T1555 | Comportamento central e documentado da família SalatStealer. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): dd17e871204619a3de34126e366221b64e684ec13e24dfc871698abe343acbff
SHA256 (script compartilhado, quinta confirmação nesta série): 96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7

IP de C2 direto: 193.221.200.26

Infraestrutura confirmada do script compartilhado:
cl-glcb907925.gcdn.co
cl-glcb907925.globalcdn.co
208.89.72.0/24
```

---

## 8. Recomendações

1. Fechar formalmente a linha de investigação do padrão de hash com zeros à esquerda aberta desde a semana 1, documentando neste relatório a conclusão de que pertence ao script `96ad1146...` e sua rede de reaproveitamento.
2. Bloquear o IP `193.221.200.26` nos controles de perímetro.
3. Priorizar o script `96ad1146...` como o indicador de hunting mais valioso de toda a base de relatórios desta série, dado seu papel confirmado em cinco investigações distintas ao longo de cinco semanas.
4. Considerar a criação de uma assinatura YARA dedicada para esse script específico, caso ainda não exista, dado seu volume de reaproveitamento.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura SalatStealer).
Correlação cruzada com os relatórios 03_2026-07_valleyrat (semana 1), 04_2026-07_scarfacestealer (semana 2), 07_2026-07_overlordrat e 08_2026-07_salatstealer (ambos semana 3), e 01_2026-08_lxbaserat (semana 5) desta mesma série.
