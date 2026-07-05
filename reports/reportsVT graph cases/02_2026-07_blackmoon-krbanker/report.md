# Threat Intelligence Report: Blackmoon (KRBanker)

**ID:** 02_2026-07_blackmoon-krbanker
**Data:** 04/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi identificada no MalwareBazaar sob a assinatura Blackmoon, também conhecida como KRBanker ou Banbra, confirmando a família apontada por 12 vendors no VirusTotal. Trata se de um trojan bancário e loader ativo desde o início dos anos 2010, historicamente voltado a instituições financeiras da Coreia do Sul, que <cite index="9-1">evoluiu para uma ferramenta de espionagem multi estágio, usando entrega via phishing e abuso de software legítimo para manter acesso encoberto em sistemas comprometidos</cite>. Relatórios recentes de 2026 mostram expansão da campanha para a Índia, com <cite index="9-1">acesso inicial obtido através de emails de spear phishing ou sites que imitam avisos fiscais do governo indiano, entregando um arquivo ZIP malicioso</cite>.

A estrutura observada no grafo é compatível com esse comportamento documentado. O executável principal carrega internamente um conjunto de 6 arquivos, entre eles um ícone que atua como elo para uma segunda etapa da infecção. Esse ícone aparece como execution parent de um arquivo RAR, o qual, ao ser extraído, libera 40 arquivos adicionais. A composição desses 40 arquivos chama atenção: 22 são arquivos de áudio OGG, 4 são imagens BMP, além de arquivos JSON, XML e um INI, todos sem detecção, misturados a 5 bibliotecas PE e 2 executáveis PE, dos quais apenas uma DLL e um arquivo de texto apresentam detecção positiva. Esse padrão de arquivos de mídia como isca é consistente com o uso de arquivos ZIP ou RAR como vetor de entrega inicial, característico da família.

No lado de rede, o executável principal contata dois IPs. Um deles, hospedado na China, está historicamente associado a certificados SSL e a um registro WHOIS antigo, sugerindo reaproveitamento de infraestrutura ao longo do tempo. O outro, hospedado no Reino Unido, comunica se com um cluster de 20 outros arquivos PE e DLL maliciosos, o que indica que esse endereço funciona como ponto de distribuição ou coleta de amostras dentro de uma campanha mais ampla, não específica dessa única investigação.

Já o RAR extraído contata o domínio legítimo `api.github.com`, além de um domínio que imita a nomenclatura de infraestrutura de DNS global da Microsoft, e se comunica com um bloco de sete IPs hospedados na Yandex Cloud, todos com detecção positiva. Essa combinação sugere abuso de serviços legítimos (GitHub) somado a infraestrutura disfarçada por meio de typosquatting, um padrão comum em campanhas que buscam se misturar a tráfego corporativo normal.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `194bef1eb8770c78baf6b4fb42b7866943d15c0cb8d96ca9fbed44171ceab307` |
| Detecção | Positiva no VirusTotal |

---

## 3. Bundled Files (6)

| SHA256 | Tipo | Observações |
|---|---|---|
| `19f3091ddad164b827cfb885fb5349c5a24520cfa8c2df8d9b4f3ce725fe89c3` | ICO | Sem detecção. Atua como execution parent do RAR descrito na seção 6. |
| `114cd917f1867fbab80c29d9b8455123e75f928e6e5fa4a74859187f968ad005` | Não informado | Sem atributos retornados pelo VT no export atual. |
| `2dedd9fb7893cae2ea314446357ddffd5c952663e5f35f96f1cd52ab88e41bde` | Não informado | Sem atributos retornados pelo VT no export atual. |
| `51733e4f25b05615ccce32d50dfc3fae67c6cd2e82637c052e71ccbe01c5cdfb` | Não informado | Sem atributos retornados pelo VT no export atual. |
| `aa53c8f2756552e492d8009bcc1004414dbd413609642ad2cafec87ae6c6227b` | Não informado | Sem atributos retornados pelo VT no export atual. |
| `f409252f8a0ff3fe06c3b974b5ed15e333cd5e9d2d1151943689cbe466b9b485` | Não informado | Sem atributos retornados pelo VT no export atual. |

---

## 4. Dropped Files diretos do executável principal (15)

| Tipo | Quantidade | Detecção |
|---|---|---|
| HTML | 3 | Nenhuma |
| PE DLL | 2 | 1 com detecção positiva (`202a1f17f5...`) |
| PE EXE | 1 | Sem detecção |
| LNK | 1 | Sem detecção |
| Sem atributos no export | 8 | Não informado |

O arquivo LNK entre os dropped files é um indicativo comum de mecanismo de persistência ou de execução indireta, prática recorrente em cadeias de infecção que buscam evitar execução direta de binários suspeitos.

---

## 5. Infraestrutura de Rede do Executável Principal

### 5.1 IPs contatados (2)

| IP | País | Observações |
|---|---|---|
| `110.42.56.61` | CN | Associado historicamente a 2 certificados SSL e a 1 registro WHOIS antigo (seção 7). Também comunica se com um segundo PE malicioso (`f690e5c3...`) além da amostra principal. |
| `51.145.123.29` | GB | Comunica se com um cluster de 20 arquivos PE e DLL adicionais, todos com detecção positiva (seção 8). Padrão de hash com múltiplos zeros à esquerda em boa parte desses arquivos, o que é estatisticamente incomum e merece registro como observação analítica. |

### 5.2 Domínios contatados (1)

| Domínio | Observações |
|---|---|
| `time.windows.com` | Domínio legítimo de sincronização de horário da Microsoft. Provavelmente tráfego padrão do sistema operacional, sem relação direta com o comportamento malicioso. |

### 5.3 URL contatada

Um nó de URL sem texto recuperado no export aparece contatado tanto pelo executável principal quanto por um segundo arquivo PE malicioso (`f690e5c3b0fbfe5a421498c3d893c74d3389b795aadd865e9bca9454eda20d29`), sugerindo que os dois binários compartilham o mesmo destino de rede, possivelmente um servidor de segundo estágio.

---

## 6. Cadeia Secundária: RAR e seus 40 Dropped Files

O ícone bundled (seção 3) aparece como execution parent do arquivo RAR `13dd583b004f57eceb9164c592c87ffde1087bc438ecbb4dc6048770e2e8271f`, sem detecção própria no VT, mas responsável por liberar 40 arquivos ao ser extraído.

### 6.1 Composição dos 40 arquivos extraídos

| Tipo | Quantidade | Detecção positiva |
|---|---|---|
| OGG (áudio) | 22 | Nenhuma |
| PE DLL | 5 | 1 (`3331f2a5fe9e1ce87ff53f8f29fba8c103c779a6c44ff0caf8aee2c22d1e8878`) |
| BMP (imagem) | 4 | Nenhuma |
| JSON | 3 | Nenhuma |
| PE EXE | 2 | Nenhuma |
| XML | 1 | Nenhuma |
| INI | 1 | Nenhuma |
| Texto | 1 | Sim (`15a94f0cf348f8671a43dff217a26e50f033d17cbbc5293515b694bf4facc5df`) |

A proporção entre arquivos de mídia (26 dos 40) e os poucos binários com detecção reforça a hipótese de um pacote de instalação disfarçado, no qual o payload malicioso é distribuído junto a recursos que simulam um aplicativo legítimo, como um jogo ou reprodutor de mídia.

### 6.2 Infraestrutura de rede do RAR

| Indicador | Tipo | Observações |
|---|---|---|
| `api.github.com` | Domínio | Serviço legítimo, possivelmente usado para hospedar ou atualizar componentes, técnica de abuso de infraestrutura confiável. |
| `default.qdr.p1.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` | Domínio | Nome construído para imitar infraestrutura de DNS global da Microsoft. Forte indício de typosquatting voltado a passar despercebido em logs de rede corporativos. |
| `140.82.114.5` | IP | Faixa pertencente ao GitHub, consistente com o domínio `api.github.com` acima. |
| `84.201.211.22`, `.24`, `.34`, `.35`, `.36`, `.38`, `.39` | IPs | Bloco na Yandex Cloud, todos com detecção positiva. Candidato mais provável a infraestrutura de comando e controle dessa cadeia. |

---

## 7. Certificados SSL e WHOIS Históricos (IP 110.42.56.61)

O IP chinês está associado a 2 certificados SSL históricos e 1 registro de WHOIS histórico no VT Graph. Os valores completos não foram detalhados no export atual, mas ficam disponíveis para consulta direta no VT Graph, clicando em cada nó correspondente.

---

## 8. Observação Analítica: Cluster de Hashes no IP Britânico

Os 20 arquivos que comunicam com o IP `51.145.123.29` apresentam, em boa parte, hashes SHA256 com sequências incomuns de zeros à esquerda. Esse padrão é estatisticamente improvável de ocorrer naturalmente em um volume tão grande de amostras distintas, o que sugere uma de duas explicações prováveis: um processo automatizado de geração ou renomeação de amostras dentro de uma mesma ferramenta de build, ou uma normalização de identificadores aplicada pelo próprio VT Graph durante a exportação. De qualquer forma, o volume de arquivos maliciosos associados a esse único IP indica que ele funciona como ponto de distribuição de uma campanha maior, não restrita a essa amostra isolada.

---

## 9. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | T1036.005 | Domínio que imita nomenclatura de infraestrutura Microsoft, além do uso de recursos de mídia como isca visual dentro do pacote. |
| Ingress Tool Transfer | T1105 | Cadeia de dropped files em dois estágios (executável principal e RAR), totalizando 55 arquivos distribuídos. |
| Web Service | T1102 | Uso de `api.github.com`, serviço legítimo, como possível ponto de hospedagem ou atualização de componentes. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação via URL compartilhada entre dois binários maliciosos distintos. |
| Obfuscated Files or Information | T1027 | Empacotamento do payload dentro de um arquivo RAR misturado a arquivos de mídia sem relação funcional aparente. |
| Phishing | T1566 | Não observado diretamente neste grafo, porém documentado como vetor de entrega padrão da família Blackmoon em campanhas recentes. |

---

## 10. IoCs Consolidados

```
SHA256 (executável principal): 194bef1eb8770c78baf6b4fb42b7866943d15c0cb8d96ca9fbed44171ceab307
SHA256 (segundo PE malicioso): f690e5c3b0fbfe5a421498c3d893c74d3389b795aadd865e9bca9454eda20d29
SHA256 (RAR intermediário): 13dd583b004f57eceb9164c592c87ffde1087bc438ecbb4dc6048770e2e8271f

Domínio typosquat: default.qdr.p1.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com

IPs suspeitos:
110.42.56.61
51.145.123.29
84.201.211.22
84.201.211.24
84.201.211.34
84.201.211.35
84.201.211.36
84.201.211.38
84.201.211.39
```

---

## 11. Recomendações

1. Bloquear o domínio typosquat e o bloco de IPs da Yandex Cloud listados na seção 6.2 nos controles de perímetro.
2. Investigar isoladamente o IP britânico `51.145.123.29`, dado o volume de arquivos maliciosos associados a ele.
3. Verificar a presença do RAR e de seus 40 arquivos extraídos no ambiente monitorado, priorizando os dois binários com detecção positiva.
4. Consultar diretamente no VT Graph os certificados SSL e o registro WHOIS histórico associados ao IP chinês, para reconstruir eventual reaproveitamento de infraestrutura.
5. Considerar o tráfego para `time.windows.com` como ruído esperado do sistema operacional, sem necessidade de bloqueio.

---

## 12. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Blackmoon e 12 detecções de vendors).
Relatórios públicos sobre a família Blackmoon / KRBanker, incluindo análise da KPMG de abril de 2026 sobre a campanha voltada à Índia.
