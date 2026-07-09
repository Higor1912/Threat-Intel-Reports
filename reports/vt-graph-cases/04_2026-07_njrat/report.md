# Threat Intelligence Report: njRAT

**ID:** 04_2026-07_njrat
**Data:** 07/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como njRAT via assinatura no MalwareBazaar, com 10 detecções entre vendors e 29 regras YARA associadas. O grafo do VT revela um achado que amplia bastante o valor dessa investigação. O endereço IP contatado pelo executável principal, `23.158.232.71`, possui histórico de resolução para 26 domínios distintos, sendo 25 deles subdomínios do serviço de DNS dinâmico `localto.net` e um deles o domínio próprio `corruptedping.com`. Nove desses domínios têm detecção positiva no VT, incluindo um chamado literalmente `ratted.localto.net`, o que deixa pouca dúvida sobre a função desse endereço como infraestrutura de comando e controle reaproveitada ao longo de múltiplas campanhas.

Além do abuso do DNS dinâmico, o grafo mostra dois outros domínios que merecem atenção. `gitea.melfely.com` aponta para uma instância própria do Gitea, sistema de hospedagem de repositórios Git auto hospedado, possivelmente usado para armazenar ou atualizar componentes do malware fora de serviços públicos monitorados. Já `netbird.corruptedping.com` sugere o uso do NetBird, ferramenta legítima de rede mesh baseada em WireGuard, uma técnica mais sofisticada que o njRAT tradicional costuma empregar, provavelmente para manter acesso persistente e criptografado à máquina comprometida depois do comprometimento inicial.

O executável principal também dropa 27 arquivos, a maioria bibliotecas PE DLL sem detecção individual, e possui um execution parent também identificado como PE malicioso, que compartilha a comunicação com o mesmo IP de infraestrutura histórica.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `fe5a033c8415522a190dec8e3072f053dfb458cd47bb208b17cb3d96740fdc34` |
| MD5 | `804346c1b45aedd1e52963906275c135` |
| Tamanho | 2.670.080 bytes |
| Primeira submissão | 07/07/2026 13:38:07 UTC |
| Detecção | 10 vendors |
| Regras YARA associadas | 29 |

---

## 3. Execution Parent

| SHA256 | Tipo | Observações |
|---|---|---|
| `38d4ed211828359eff5ec6e1664ac758b42f2fa49232bbbc72d4f8b0a1f18307` | PE EXE | Detecção positiva. Comunica com o mesmo IP de infraestrutura histórica descrito na seção 5. |

---

## 4. Bundled Files e Dropped Files

### 4.1 Bundled files (14)

| Tipo | Observações |
|---|---|
| XML | 1 arquivo, sem detecção. |
| JavaScript | 1 arquivo, sem detecção. |
| Sem atributos no export | 12 arquivos. |

### 4.2 Dropped files (27)

| Tipo | Quantidade | Detecção |
|---|---|---|
| PE DLL | 23 | Nenhuma individualmente |
| INI | 1 | Nenhuma |
| CSV | 1 | Nenhuma |
| Texto | 1 | Nenhuma |
| Sem atributos no export | 2 | Não informado |

Nenhum dos dropped files apresentou detecção individual positiva. O volume alto de DLLs sem assinatura própria é consistente com o comportamento típico do njRAT, que costuma se apoiar fortemente no executável principal para a lógica maliciosa, mantendo os componentes auxiliares como bibliotecas de suporte legítimas ou levemente ofuscadas.

---

## 5. Infraestrutura de Rede

### 5.1 IP Central: 23.158.232.71 (Estados Unidos)

Esse endereço é o achado mais relevante da investigação. Contatado diretamente tanto pelo executável principal quanto pelo execution parent, ele apresenta um histórico de resolução de DNS com 26 domínios distintos, reunidos na tabela abaixo.

| Domínio | Detecção |
|---|---|
| `jj4sl51rmi.localto.net` | Positiva |
| `wd9ejnoex7.localto.net` | Positiva |
| `us1.localto.net` | Positiva |
| `azxq0ap.localto.net` | Positiva |
| `eh8tpi6aym.localto.net` | Positiva |
| `dapodikalwafa.localto.net` | Positiva |
| `neweug0d6p.localto.net` | Positiva |
| `ratted.localto.net` | Positiva |
| `corruptedping.com` | Positiva |
| `xkslgfwfji.localto.net` | Nenhuma |
| `z8yjkuzqwp.localto.net` | Nenhuma |
| `4bk89xdasy.localto.net` | Nenhuma |
| `kyonkthvbq.localto.net` | Nenhuma |
| `xzefw94mr.localto.net` | Nenhuma |
| `fkccv4u13s.localto.net` | Nenhuma |
| `cnlhr1x4tu.localto.net` | Nenhuma |
| `kbuyxc6oi5.localto.net` | Nenhuma |
| `ajy4fymouh.localto.net` | Nenhuma |
| `xjtrna4cez.localto.net` | Nenhuma |
| `cl7a18ovby.localto.net` | Nenhuma |
| `dxgcltwsng.localto.net` | Nenhuma |
| `eu1mmsbzwt.localto.net` | Nenhuma |
| `gitea.melfely.com` | Nenhuma |
| `melfely.com` | Nenhuma |
| `netbird.corruptedping.com` | Nenhuma |
| `tisps1okhy.proxyaxe.com` | Nenhuma |
| `p02.showht.com` | Nenhuma |

O padrão de dezenas de subdomínios aleatórios sob `localto.net` apontando para o mesmo IP ao longo do tempo é típico de builders de RAT que geram um endereço de DNS dinâmico único a cada compilação, prática comum entre operadores de njRAT para dificultar bloqueio simples por domínio.

O IP também possui 3 certificados SSL históricos e 1 registro de WHOIS histórico associados, cujos valores completos não vieram detalhados no export atual e ficam disponíveis para consulta direta no VT Graph.

### 5.2 Domínio contatado diretamente pelo executável principal

| Domínio | Observações |
|---|---|
| `ipwhois.app` | Serviço legítimo de consulta de geolocalização de IP. Uso comum em RATs para checar a localização da vítima antes de prosseguir com a execução. |

### 5.3 IPs adicionais contatados pelo executável principal

| IP | Observações |
|---|---|
| `104.26.6.74`, `104.26.7.74`, `172.67.70.190` | Faixa Cloudflare, provável proxy reverso para os domínios de DNS dinâmico. |
| `162.159.36.2` | Faixa Cloudflare, mesmo padrão. |

### 5.4 URL contatada

O grafo lista uma URL contatada pelo executável principal, porém sem o texto completo disponível no export. Recomenda se abrir o nó diretamente no VT Graph para obter o valor exato.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Dynamic Resolution | T1568 | Uso extensivo de subdomínios sob o serviço de DNS dinâmico localto.net, com histórico de dezenas de resoluções para o mesmo IP. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação de rede via domínios e IPs associados ao Cloudflare como proxy. |
| System Location Discovery | T1614 | Consulta ao serviço `ipwhois.app` para checagem de geolocalização da vítima. |
| Web Service | T1102 | Uso de instância própria do Gitea, possivelmente para hospedar ou atualizar componentes fora de serviços públicos monitorados. |
| Multi hop Proxy | T1090 | Indício de uso do NetBird, ferramenta de rede mesh baseada em WireGuard, como possível canal de acesso persistente e criptografado. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): fe5a033c8415522a190dec8e3072f053dfb458cd47bb208b17cb3d96740fdc34
SHA256 (execution parent): 38d4ed211828359eff5ec6e1664ac758b42f2fa49232bbbc72d4f8b0a1f18307

IP de infraestrutura histórica: 23.158.232.71

Domínios maliciosos confirmados:
jj4sl51rmi.localto.net
wd9ejnoex7.localto.net
us1.localto.net
azxq0ap.localto.net
eh8tpi6aym.localto.net
dapodikalwafa.localto.net
neweug0d6p.localto.net
ratted.localto.net
corruptedping.com

Domínios de suporte à campanha, sem detecção individual:
gitea.melfely.com
melfely.com
netbird.corruptedping.com
tisps1okhy.proxyaxe.com
```

---

## 8. Recomendações

1. Bloquear o IP `23.158.232.71` e todo o padrão de subdomínios sob `localto.net` associados a ele nos controles de perímetro.
2. Monitorar tráfego de saída para `netbird.corruptedping.com`, dado o risco de estabelecimento de túnel persistente via WireGuard.
3. Verificar a presença das 23 DLLs dropadas pelo executável principal no ambiente monitorado, mesmo sem detecção individual, já que costumam operar como suporte direto à funcionalidade do RAT.
4. Consultar diretamente no VT Graph os certificados SSL e o registro WHOIS histórico do IP central, para reconstruir eventual reaproveitamento de infraestrutura ao longo do tempo.
5. Considerar o tráfego para `ipwhois.app` e para a faixa Cloudflare como comportamento operacional do malware, não como alvo direto de bloqueio isolado, já que fazem parte da cadeia de proxy do C2.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura njRAT).
