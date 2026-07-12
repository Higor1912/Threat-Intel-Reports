# Threat Intelligence Report: NanoCore

**ID:** 07_2026-07_nanocore
**Data:** 10/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como NanoCore via assinatura no MalwareBazaar, com 20 detecções entre vendors e 15 regras YARA associadas, número expressivo que reflete o quanto essa família já é conhecida e documentada desde seu surgimento em 2013. O nome do arquivo, `xoilacbongda-wc2026a.tv.exe`, aponta para um vetor de entrega temático: `xoilac` é o nome de um site vietnamita de transmissão pirata de futebol, e a combinação com `wc2026` sugere isca relacionada à Copa do Mundo de 2026, prática recorrente de campanhas que se aproveitam de grandes eventos esportivos para atrair vítimas em busca de transmissões gratuitas.

Diferente das investigações anteriores desta coleção, o grafo desta amostra é significativamente mais raso na cadeia direta de rede. O executável principal dropa apenas 6 arquivos, sem contatar domínios ou IPs diretamente. Entre os dropados, uma DLL com detecção positiva contata um pequeno conjunto de 6 IPs pertencentes à faixa do Google, comportamento consistente com o uso histórico do NanoCore de servidores SMTP do Gmail como canal de checagem de conectividade ou, em versões mais antigas da família, como rota de exfiltração de dados via email.

Vale registrar que boa parte do volume total do grafo exportado (826 nós) vem de coleções públicas da comunidade VT associadas ao hash da DLL, não de infraestrutura de rede expandida diretamente a partir desta amostra. Essas coleções reforçam a atribuição à família NanoCore, mas não acrescentam indicadores de rede específicos e verificáveis para esta investigação, então foram tratadas aqui apenas como corroboração de contexto, não como fonte de IoCs adicionais.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d` |
| MD5 | `f85edfbd3b5d8c22774f4239c920727e` |
| Nome do arquivo | `xoilacbongda-wc2026a.tv.exe` |
| Tamanho | 207.872 bytes |
| Primeira submissão | 10/07/2026 01:45:05 UTC |
| Detecção | 20 vendors |
| Regras YARA associadas | 15 |

---

## 3. Dropped Files (6)

| SHA256 | Tipo | Detecção | Observações |
|---|---|---|---|
| `3e70b8c0039e499fdb46c4630d8178cbb82b49bf09358ebedfeb5a9ccdade175` | XML | Nenhuma | Provável arquivo de configuração. |
| `72e0743c301b5dd7c36bf851160e03e06df791feaa9fd1e9c5be34e8739a5fe6` | Não informado | Sem atributos no export | |
| `9487e6b6fc92f87f451e2a1d2b74686911b86889c42e2e39552499d88d8e4ae4` | Não informado | Sem atributos no export | |
| `c0df9249ce7a5a4d92ee5c59b35895451ed462fa4b12c04349d5bb5ff0e7cd2a` | Não informado | Sem atributos no export | |
| `01e3b18bd63981decb384f558f0321346c3334bb6e6f97c31c6c95c4ab2fe354` | PE DLL | Positiva | Carrega 11 arquivos bundled, majoritariamente ícones e imagens, prováveis recursos de interface falsa. Associada a múltiplas coleções públicas confirmando NanoCore, detalhado na seção 5. |
| `61e9d5c0727665e9ef3f328141397be47c65ed11ab621c644b5bbf1d67138403` | PE DLL | Positiva | Contata os 6 IPs listados na seção 4. |

---

## 4. Infraestrutura de Rede

### 4.1 IPs contatados pela segunda DLL (6)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `173.194.70.100` | US | Positiva | Faixa do Google, provável SMTP relay. |
| `173.194.70.101` | US | Positiva | Mesma faixa. |
| `173.194.70.102` | US | Positiva | Mesma faixa. |
| `173.194.70.113` | US | Nenhuma | Mesma faixa. |
| `173.194.70.138` | US | Nenhuma | Mesma faixa. |
| `173.194.70.139` | US | Nenhuma | Mesma faixa. |

O contato exclusivo com um bloco contíguo de IPs do Google é consistente com o comportamento historicamente documentado do NanoCore de usar servidores SMTP do Gmail, seja para checagem de conectividade antes de ativar rotinas maliciosas, seja como canal de exfiltração de dados coletados por email em versões mais antigas da família.

---

## 5. Corroboração via Coleções Públicas

A DLL `01e3b18b...` aparece referenciada em 11 coleções públicas da comunidade VT, entre elas nomeadas diretamente como "Nanocore RAT" e "NanoCore", além de outras referências genéricas a atividade maliciosa relacionada. Essas coleções servem apenas como confirmação adicional da atribuição de família já estabelecida pelo MalwareBazaar, sem indicadores de rede novos e verificáveis para esta investigação específica.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Nome de arquivo associado a isca de transmissão pirata de futebol ligada à Copa do Mundo de 2026. |
| Application Layer Protocol: Mail Protocols | T1071.003 | Contato exclusivo com faixa de IPs do Google, consistente com uso histórico de SMTP pela família. |
| Ingress Tool Transfer | T1105 | Queda de 6 arquivos adicionais a partir do executável principal. |
| Archive Collected Data | T1560 | Comportamento característico do NanoCore de empacotar dados coletados antes da exfiltração. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): dacc3d21d8d1e49fd7728f3500943b9eddd80589264d939fbe1fd880fe03938d
SHA256 (DLL com contato de rede): 61e9d5c0727665e9ef3f328141397be47c65ed11ab621c644b5bbf1d67138403
SHA256 (DLL confirmada em coleções públicas): 01e3b18bd63981decb384f558f0321346c3334bb6e6f97c31c6c95c4ab2fe354

Faixa de IPs contatada:
173.194.70.100
173.194.70.101
173.194.70.102
173.194.70.113
173.194.70.138
173.194.70.139
```

---

## 8. Recomendações

1. Verificar a presença das duas DLLs listadas na seção 3 no ambiente monitorado, priorizando a que contata a faixa de IPs do Google.
2. Monitorar tráfego SMTP de saída para a faixa `173.194.70.0/24`, especialmente originado de processos não relacionados a clientes de email legítimos.
3. Orientar usuários finais sobre o risco de sites de transmissão pirata de eventos esportivos como vetor de entrada, dado o tema do arquivo analisado.
4. Como o grafo desta amostra trouxe poucos indicadores de rede diretos, considerar nova exportação do VT Graph após expandir manualmente os nós sem atributos (`72e0743c`, `9487e6b6`, `c0df9249`) para checar se possuem dados adicionais não capturados neste export.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura NanoCore).
