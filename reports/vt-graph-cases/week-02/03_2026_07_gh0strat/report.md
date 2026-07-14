# Threat Intelligence Report: Gh0stRAT

**ID:** week-02/03_2026-07_gh0strat
**Data:** 14/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Gh0stRAT via assinatura no MalwareBazaar, com 8 detecções entre vendors e 5 regras YARA associadas. O nome do arquivo, `Four Seasons Purchase List_pdf.exe`, segue o truque clássico de dupla extensão, fazendo parecer um PDF de lista de compras quando na verdade é um executável, isca típica de phishing direcionado a áreas de compras ou financeiro corporativo.

O grafo confirma um único ponto de comando e controle, mas com um histórico de reaproveitamento bastante rico. O domínio `qishuiwg.com`, resolvendo para o IP `154.23.184.251` em Hong Kong, é contatado por esta amostra e por outros 8 arquivos maliciosos diferentes no mesmo grafo, entre executáveis PE e arquivos RAR. O histórico de resolução desse IP ao longo do tempo revela 20 domínios distintos, com um padrão temático muito claro: praticamente todos remetem a plataformas de apostas online em língua chinesa, com nomes como `hg348bet`, `mgm118` e variações do padrão `855a`. Esse é o segundo caso desta série a mostrar C2 hospedado atrás de infraestrutura com tema de apostas online, depois do QuasarRAT na semana anterior, o que sugere que esse tipo de hospedagem, seja por conivência do provedor, seja por reaproveitamento oportunista de domínios expirados de cassino, segue sendo um padrão recorrente entre operadores de RAT na região.

O executável principal dropa 6 arquivos, dos quais dois têm detecção positiva e servem como núcleo funcional do RAT, cada um carregando seus próprios recursos bundled.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `93b19bc56952ae1e82f1f41db49f455316736e2b8d161e64b115a150d8dcf204` |
| MD5 | `3c230061e5a16cc559b0a7f025f08250` |
| Nome do arquivo | `Four Seasons Purchase List_pdf.exe` |
| Tamanho | 20.027.449 bytes |
| Primeira submissão | 14/07/2026 12:10:36 UTC |
| Detecção | 8 vendors |
| Regras YARA associadas | 5 |

O tamanho do arquivo, cerca de 20 MB, é bem acima do padrão para um dropper simples, possivelmente porque o pacote já inclui os componentes que aparecem entre os dropped files listados a seguir.

---

## 3. Dropped Files (6)

| SHA256 | Tipo | Detecção | Observações |
|---|---|---|---|
| `76e4546ab19d251960e6e428d65367c1c210b4053b9d02a1fee3de9b138e7a28` | PE DLL | Positiva | Tem o executável principal como seu próprio execution parent e carrega 19 arquivos bundled adicionais, majoritariamente sem atributos no export. |
| `fdb037f85c50f3c449c5d43a6b513545ea3fed03020ebf4205e8931c7dc852a4` | PE EXE | Positiva | Carrega 6 arquivos bundled próprios. |
| `388a796580234efc95f3b1c70ad4cb44bfddc7ba0f9203bf4902b9929b136f95` | PE EXE | Nenhuma | |
| `056c93579849ef9b8f87bb50aec72c953b95cc6d2b56b78283ca5723de74af77` | Não informado | Sem atributos no export | |
| `2ad1bda161a45a9988c3dc8a43646628341675c733843e3fea7faf15c018f766` | Não informado | Sem atributos no export | |
| `60b75aa8e30ca89d43c2d29fab19b4aed25547d27c53d86f4804783e126379d2` | Não informado | Sem atributos no export | |

---

## 4. Infraestrutura de Rede

### 4.1 IP de Comando e Controle: 154.23.184.251 (Hong Kong)

Esse endereço é o achado central da investigação, tanto pelo volume de arquivos que o contatam quanto pelo histórico de resolução DNS.

**Arquivos que comunicam com o mesmo IP (9 no total, incluindo a amostra atual)**

| SHA256 | Tipo |
|---|---|
| `93b19bc56952ae1e82f1f41db49f455316736e2b8d161e64b115a150d8dcf204` | PE EXE (amostra atual) |
| `765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce` | PE EXE |
| `8dd17c3c0cef5f36e2c43c59ef88077c004cc283565ff4429107fe7615537ede` | PE EXE |
| `b4d4ab01efb60f51f3a799085511847007b1a49aa5248c756e1544261dc408e9` | RAR |
| `4208efa19dfbbe1dcdc1bfd38d7c8dfb9d92d7f68f7cf2a92df1859bfafb2f89` | PE EXE |
| `50cef8584d913e87586d8ccfbc0a2858926faebedcfb6defb1e40a4ea4e05206` | RAR |
| `6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543` | RAR |
| `afbb03825856a497418ce316d731a5d40e17fc86654852bfd3527ef0367da101` | PE EXE |
| `e10a2c99fc7fcf94ba2d35e494d4f498cf03e905e9e3c4335a04a235891e1a34` | PE EXE |

**Histórico de resolução DNS (20 domínios, tema de apostas online em língua chinesa)**

| Domínio | Detecção |
|---|---|
| `qishuiwg.com` | Positiva |
| `www.855a666.com`, `855a666.com` | Positiva |
| `www.99348pk.com`, `99348pk.com` | Positiva |
| `2.easydream.bet` | Nenhuma |
| `855a.xyz`, `348a.app`, `www.855a6.app`, `855a6.app` | Nenhuma |
| `www.hg348bet-855a77-855a7.com`, `hg348bet-855a77-855a7.com` | Nenhuma |
| `www.mgm118.xyz`, `mgm118.xyz` | Nenhuma |
| `www.m1377.com`, `m1377.com` | Nenhuma |
| `www.hg3800.cc`, `hg3800.cc` | Nenhuma |
| `www.gg12322.com`, `gg12322.com` | Nenhuma |

O IP também possui 3 registros de WHOIS histórico e 1 certificado SSL histórico associados, cujos valores completos não vieram detalhados no export atual e ficam disponíveis para consulta direta no VT Graph.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Nome de arquivo com dupla extensão simulando um PDF de lista de compras. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de comando e controle em Hong Kong. |
| Web Service | T1102 | Reaproveitamento confirmado do mesmo domínio e IP por 9 arquivos maliciosos distintos. |
| Ingress Tool Transfer | T1105 | Queda de 6 arquivos adicionais a partir do executável principal, dois deles com bundled files próprios. |

---

## 6. IoCs Consolidados

```
SHA256 (executável principal): 93b19bc56952ae1e82f1f41db49f455316736e2b8d161e64b115a150d8dcf204
SHA256 (DLL núcleo do RAT): 76e4546ab19d251960e6e428d65367c1c210b4053b9d02a1fee3de9b138e7a28
SHA256 (segundo componente PE): fdb037f85c50f3c449c5d43a6b513545ea3fed03020ebf4205e8931c7dc852a4

Domínio de C2: qishuiwg.com
IP de C2: 154.23.184.251

Outros arquivos confirmados no mesmo C2:
765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce
8dd17c3c0cef5f36e2c43c59ef88077c004cc283565ff4429107fe7615537ede
b4d4ab01efb60f51f3a799085511847007b1a49aa5248c756e1544261dc408e9
```

---

## 7. Recomendações

1. Bloquear o domínio `qishuiwg.com` e o IP `154.23.184.251` nos controles de perímetro.
2. Verificar a presença das duas DLLs e do segundo executável com detecção positiva (seção 3) no ambiente monitorado.
3. Orientar equipes de compras e financeiro sobre o risco de anexos com dupla extensão simulando PDF, dado o tema da isca usada nesta amostra.
4. Consultar diretamente no VT Graph os registros de WHOIS histórico e o certificado SSL do IP de C2, para reconstruir a linha do tempo de reaproveitamento dessa infraestrutura.
5. Adicionar o padrão de domínios de apostas online em língua chinesa observado aqui e no relatório de QuasarRAT da semana anterior como categoria de hunting recorrente para futuras investigações desta série.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Gh0stRAT).
