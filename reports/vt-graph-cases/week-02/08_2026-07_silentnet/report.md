# Threat Intelligence Report: SilentNet

**ID:** week-02/08_2026-07_silentnet
**Data:** 18/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como SilentNet via assinatura no MalwareBazaar, com 9 detecções entre vendors e 5 regras YARA associadas. O nome do arquivo, `Launcher.exe`, descreve exatamente seu papel na cadeia: esse executável não carrega a lógica maliciosa diretamente, ele desempacota um ambiente Python completo em disco, com 79 arquivos Python e 27 bibliotecas DLL associadas ao interpretador, para então executar o payload real como script.

O grafo confirma dois objetivos financeiros combinados nessa amostra, ambos sinalizados pelas coleções públicas associadas: mineração de criptomoeda via XMRig e interação direta com a rede Polygon. O segundo ponto é o mais incomum. A amostra contata cinco endpoints RPC distintos da blockchain Polygon, incluindo `polygon-rpc.com`, `rpc-mainnet.matic.quiknode.pro` e `polygon-bor-rpc.publicnode.com`, todos com detecção positiva apesar de serem serviços de infraestrutura blockchain legítimos e amplamente usados. Esse padrão é característico de malware que realiza transações diretamente na blockchain, seja para varrer carteiras comprometidas, seja para interagir com contratos maliciosos, comportamento mais sofisticado do que o cryptojacking tradicional isolado.

O domínio de comando e controle, `sltnnt.ru`, reflete diretamente o nome da assinatura da família. Um segundo domínio contatado, `thisisafalsepositive.st`, também com detecção positiva, é quase certamente uma provocação deliberada do desenvolvedor do malware direcionada a analistas, e não tem função técnica aparente além de ridicularizar ferramentas de detecção automatizada. Ambos os domínios são contatados por esta amostra e por um segundo arquivo malicioso no mesmo grafo, confirmando reaproveitamento de infraestrutura mesmo dentro dessa única investigação.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `6c9020a812a13890e4f7f7b16f7ec4512385e3c9ad86bc62ac7ba5a6bd6673b4` |
| MD5 | `c8d1e644c89b63334e8b6af6f35d091e` |
| Nome do arquivo | `Launcher.exe` |
| Tamanho | 1.138.688 bytes |
| Primeira submissão | 18/07/2026 10:54:41 UTC |
| Detecção | 9 vendors |
| Regras YARA associadas | 5 |

---

## 3. Coleções Associadas

| Coleção | Observações |
|---|---|
| XMRig | Confirma o componente de mineração de criptomoeda. |
| xmrig | Segunda entrada, mesma confirmação por outra submissão da comunidade. |

---

## 4. Ambiente Python Empacotado (120 Dropped Files)

| Tipo | Quantidade | Detecção individual |
|---|---|---|
| Python (código fonte ou bytecode) | 79 | Nenhuma |
| PE DLL | 27 | Nenhuma |
| Texto | 7 | Nenhuma |
| ZIP | 3 | Nenhuma |
| PE EXE | 2 | Nenhuma |
| PowerShell | 1 | Nenhuma |
| INI | 1 | Nenhuma |

Nenhum dos 120 arquivos apresentou detecção individual, o que é esperado. Um interpretador Python legítimo embutido não é malicioso por si só, componente por componente. A lógica maliciosa provavelmente está concentrada em um ou poucos scripts Python específicos dentro desse conjunto, não identificáveis individualmente a partir dos metadados disponíveis no export atual.

O bundled file do tipo imagem ISO entre os 7 arquivos carregados diretamente pelo executável principal é consistente com uma técnica de empacotamento de instalador, comum para acomodar um ambiente de execução completo sem depender de dependências já presentes no sistema da vítima.

---

## 5. Infraestrutura de Rede

### 5.1 Domínios contatados relevantes (7 de 20)

| Domínio | Detecção | Observações |
|---|---|---|
| `sltnnt.ru` | Positiva | Domínio de C2, nome derivado diretamente da assinatura SilentNet. Também contatado por um segundo arquivo malicioso no mesmo grafo. |
| `thisisafalsepositive.st` | Positiva | Provável provocação do desenvolvedor a analistas e ferramentas de detecção. Mesmo padrão de reaproveitamento do domínio acima. |
| `polygon-rpc.com` | Positiva | Endpoint RPC oficial da rede Polygon. |
| `rpc-mainnet.matic.quiknode.pro` | Positiva | Endpoint RPC da Polygon via QuickNode. |
| `polygon-bor-rpc.publicnode.com` | Positiva | Endpoint RPC da Polygon via PublicNode. |
| `polygon-public.nodies.app` | Positiva | Endpoint RPC da Polygon via Nodies. |
| `polygon.rpc.subquery.network` | Positiva | Endpoint RPC da Polygon via SubQuery. |
| `api.zan.top` | Positiva | Agregador de RPC multi chain operado pela Ant Group. |

### 5.2 Domínios sem detecção, prováveis dependências legítimas do ambiente Python

`bootstrap.pypa.io`, `files.pythonhosted.org`, `pypa.io`, `pypi.org`, `python.org`, `www.python.org`, `1rpc.io`, `endpoints.omniatech.io`, além de infraestrutura de CDN (Fastly, Akamai) e domínios da Microsoft. Consistentes com a instalação ou atualização legítima do ambiente Python empacotado.

### 5.3 IPs contatados relevantes (2 de 31)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `185.178.208.191` | RU | Positiva | Candidato mais provável a infraestrutura de C2 direta. |
| `150.171.109.65`, `150.171.109.114`, `150.171.109.146`, `150.171.109.148`, `150.171.110.146` | US | Positiva | Faixa de servidores de saída de email da Microsoft, mesmo bloco observado na investigação de ScarfaceStealer nesta mesma semana. Provável reputação de uso abusivo, não necessariamente comportamento malicioso direto do bloco. |

O restante dos 31 IPs corresponde a faixas legítimas de Cloudflare, Fastly, Akamai e Alibaba Cloud, sem detecção, prováveis dependências do ambiente Python e dos serviços de RPC blockchain.

### 5.4 URLs Contatadas

3 das 5 URLs listadas têm detecção positiva, sem texto completo disponível no export atual.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Resource Hijacking | T1496 | Componente de mineração de criptomoeda confirmado pelas coleções XMRig associadas. |
| Financial Theft | T1657 | Interação direta com múltiplos endpoints RPC da rede Polygon, comportamento consistente com varredura ou drenagem de carteiras. |
| Deploy Container / Ingress Tool Transfer | T1105 | Empacotamento e implantação de um ambiente Python completo em disco a partir de um único launcher. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o domínio de C2 `sltnnt.ru`. |

---

## 7. IoCs Consolidados

```
SHA256 (launcher principal): 6c9020a812a13890e4f7f7b16f7ec4512385e3c9ad86bc62ac7ba5a6bd6673b4

Domínio de C2: sltnnt.ru
Domínio de provocação a analistas: thisisafalsepositive.st
IP de C2: 185.178.208.191

Endpoints RPC Polygon contatados (uso malicioso confirmado):
polygon-rpc.com
rpc-mainnet.matic.quiknode.pro
polygon-bor-rpc.publicnode.com
polygon-public.nodies.app
polygon.rpc.subquery.network
api.zan.top
```

---

## 8. Recomendações

1. Bloquear `sltnnt.ru` e o IP `185.178.208.191` nos controles de perímetro.
2. Monitorar chamadas para os endpoints RPC da Polygon listados a partir de processos não relacionados a carteiras ou aplicações Web3 legítimas conhecidas no ambiente, já que esse é o indicador mais específico de atividade maliciosa financeira nesta amostra.
3. Investigar os 79 arquivos Python dropados para identificar qual script específico contém a lógica de mineração e de interação com a blockchain, já que nenhum componente individual do ambiente empacotado apresentou detecção própria.
4. Correlacionar o bloco de IPs `150.171.109.0/24` com o achado equivalente no relatório de ScarfaceStealer desta mesma semana, para avaliar se ambas as amostras passam pela mesma infraestrutura de terceiros ou apenas coincidem em reputação de bloco.
5. Considerar o tráfego para PyPI, python.org e CDNs legítimas como ruído esperado do ambiente empacotado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura SilentNet).
Coleções públicas do VT Graph: "XMRig" e "xmrig".
