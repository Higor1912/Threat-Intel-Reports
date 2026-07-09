# Threat Intelligence Report: ValleyRAT

**ID:** 03_2026-07_valleyrat
**Data:** 05/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como ValleyRAT via assinatura no MalwareBazaar. O grafo do VT reforça essa atribuição por meio de duas coleções associadas diretamente ao arquivo principal: DonutLoader, referente à técnica de conversão de PE em shellcode usada como estágio intermediário, e 银狐 (SilverFox), o cluster de ator chinês conhecido por distribuir ValleyRAT junto a outras famílias como Gh0stRAT e PurpleFox, normalmente mirando usuários de língua chinesa através de instaladores falsos.

A cadeia de infecção observada tem três estágios claros. No primeiro, um endereço IP hospedado na Índia funciona como ponto central de distribuição, comunicando se com pelo menos três arquivos ZIP distintos, todos com detecção positiva. Dois desses ZIPs aparecem como execution parents diretos do payload principal, um executável PE também com detecção positiva e identificado como o núcleo do ValleyRAT nesta cadeia. O payload principal, por sua vez, carrega 59 arquivos empacotados, majoritariamente recursos benignos (imagens PNG, XML, CAB, uma imagem ISO), típicos de um instalador legítimo usado como disfarce, e ainda libera 15 arquivos adicionais, dos quais 4 bibliotecas DLL apresentam detecção positiva.

Do lado de rede, o payload principal contata um pequeno conjunto de IPs que inclui o mesmo hub indiano, um endereço em Hong Kong ligado à Tencent Cloud e infraestrutura de CDN da Fastly, além de domínios legítimos da GlobalSign e da Microsoft usados para validação de certificado e atualização, prováveis ruídos operacionais do sistema. Um arquivo JavaScript relacionado, presente na mesma coleção, comunica com um IP separado nos Estados Unidos e contata majoritariamente infraestrutura da Microsoft e Akamai, com uma exceção: um domínio de CDN da Gcore que aparece com detecção positiva, possível ponto de reaproveitamento de infraestrutura legítima para fins maliciosos.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `77e220b261fbfcc539ecab0d3567603ee3e261c02ad1a26c7ce19e513f240a4d` |
| Detecção | Positiva no VirusTotal |
| Coleções associadas | DonutLoader; 银狐 (SilverFox) |

---

## 3. Cadeia de Distribuição (Execution Parents)

O payload principal possui 3 execution parents, todos com detecção positiva.

| SHA256 | Tipo | Observações |
|---|---|---|
| `44a11ca55c3bdc05f3cfa1b323944cefd0ca0982f0368fffd2aec4ce6676b9b1` | ZIP | Comunica com o IP indiano central (seção 5.1). |
| `65c8b786b209421b36de3e7d13218c9f0c67257aad2f7236afebe0a40b453fd3` | ZIP | Comunica com o mesmo IP indiano central. |
| `bbc61f3eee2100bf32cee55ea7e221f020fa3bdb37adf51f2d49ec68e2733bae` | PE EXE | Também contata o IP indiano central e é responsável por 14 dropped files adicionais, incluindo o próprio payload principal. |

Um quarto arquivo ZIP, não ligado diretamente como execution parent mas comunicando com o mesmo IP indiano, reforça a hipótese de que esse endereço funciona como hub de distribuição para múltiplos pacotes dessa campanha.

| SHA256 | Tipo | Observações |
|---|---|---|
| `301145570a82107eae808c99d6da1cf8e5b0addb11d6ce6d48577bd8c16f9a9a` | ZIP | Comunica com o mesmo IP indiano central e contata separadamente 5 IPs adicionais nos Estados Unidos, prováveis infraestrutura de CDN ou hospedagem secundária. |

---

## 4. Bundled Files e Dropped Files do Payload Principal

### 4.1 Bundled files (59)

A grande maioria são recursos sem detecção, consistentes com um instalador legítimo usado como fachada.

| Tipo | Quantidade aproximada |
|---|---|
| PNG | 8 |
| CAB | 2 |
| XML | 1 |
| Texto | 2 |
| ISO Image | 1 |
| Sem atributos no export | 45 |

### 4.2 Dropped files (15)

| SHA256 | Tipo | Detecção |
|---|---|---|
| `c1dbde75f6548c53c81d68855006e7d40673feb10c688dd1e31053205e19fd13` | PE DLL | Positiva |
| `fa17cb6c2520bc6a68b759eed3c727cf21c7880984a2174ff4d3e159f9332dcc` | PE DLL | Positiva |
| `2827f9b6576b43f16e1f963aeb6f1f6e1df195d66f269c071e804a96aaafbed9` | PE DLL | Positiva |
| `7cb09c17cd73bc602513ff039fa95642416758f2680877c4d73768badb60852b` | PE DLL | Positiva |
| `bc01d5edd77abd191d7e1587da951297b777ba9a35df7742d4e57e30b1d2043e` | PE DLL | Nenhuma |
| `c2972fba53e166eb94af5d086b6643fa60632f12bf976fcb25304ce0803d9231` | PE EXE | Nenhuma |
| `b3d510ef04275ca8e698e5b3cbb0ece3949ef9252f0cdc839e9ee347409a2209` | Texto | Nenhuma |
| Demais 8 arquivos | Não informado | Sem atributos no export |

As 4 DLLs com detecção positiva são o componente mais relevante para investigação local, já que representam os módulos que efetivamente carregam a funcionalidade do RAT no sistema comprometido.

---

## 5. Infraestrutura de Rede

### 5.1 IPs contatados pelo payload principal (5)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `27.124.18.166` | IN | Positiva | Hub central de distribuição, contatado também pelo execution parent PE e por ao menos 3 arquivos ZIP distintos (seção 3). Infraestrutura mais relevante desta investigação. |
| `43.132.105.206` | HK | Nenhuma | Tencent Cloud. Possível ponto de hospedagem secundário, comum em campanhas do cluster SilverFox. |
| `151.101.66.133` | US | Nenhuma | Fastly CDN. Provável tráfego de distribuição de conteúdo legítimo. |
| `224.0.0.251` | ZZ | Nenhuma | Multicast mDNS. Ruído de rede local. |
| `224.0.0.252` | ZZ | Positiva | Multicast LLMNR. Detecção provavelmente ligada a reputação de uso abusivo do protocolo, não ao endereço em si. |

### 5.2 Domínios contatados pelo payload principal (7)

| Domínio | Observações |
|---|---|
| `alidata-1327210346.cos.ap-hongkong.myqcloud.com` | Armazenamento de objetos na Tencent Cloud, Hong Kong. Possível repositório de estágios adicionais. |
| `crl.globalsign.com`, `globalsign.com`, `ocsp.globalsign.com`, `ocsp2.globalsign.com` | Validação de certificado digital. Tráfego padrão de verificação de assinatura, não malicioso por si só. |
| `ctldl.windowsupdate.com`, `windowsupdate.com` | Atualização da lista de certificados confiáveis do Windows. Ruído esperado do sistema operacional. |

### 5.3 IP contatado pelo execution parent PE (bbc61f3e), além do hub indiano

| IP | País | Detecção | Observações |
|---|---|---|---|
| `104.18.38.233`, `172.64.149.23` | ZZ | Nenhuma | Faixa Cloudflare. |
| `199.232.210.172` | US | Nenhuma | Fastly CDN. |
| `52.78.169.250` | KR | Nenhuma | Coreia do Sul, origem não confirmada. |
| `8.8.8.8` | US | Nenhuma | Resolver público Google, checagem de conectividade. |
| `ff02::1:3` | ZZ | Nenhuma | Multicast IPv6 (LLMNR). |

### 5.4 Artefato relacionado: JavaScript comunicando com IP separado

Um arquivo JavaScript com detecção positiva (`00001f277697bab3cd2412d92a1926328eb8f864fdb27043e6f604cd748b594a`) aparece na mesma coleção do grafo, comunicando com o IP `92.223.96.6` (US, detecção positiva), o mesmo endereço presente na lista de contatos do execution parent PE. Esse arquivo contata majoritariamente infraestrutura legítima da Microsoft, Akamai e Bing, com uma exceção relevante: o domínio `cl-glcb907925.gcdn.co`, hospedado na Gcore CDN, apresenta detecção positiva e é o candidato mais provável a ponto de comando disfarçado entre o tráfego de telemetria legítimo.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | T1036.005 | Instalador com 59 arquivos bundled majoritariamente benignos, disfarçando o payload real entre recursos legítimos. |
| Ingress Tool Transfer | T1105 | Cadeia de distribuição em múltiplos estágios via ZIP, com ao menos 3 pacotes distintos associados ao mesmo hub de distribuição. |
| Reflective Code Loading | T1620 | Uso da técnica DonutLoader, que converte executáveis PE em shellcode para carregamento na memória sem escrita direta em disco. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação via domínio de CDN com detecção positiva, possivelmente usado como canal de comando disfarçado entre tráfego legítimo. |
| Web Service | T1102 | Uso de armazenamento em nuvem legítimo (Tencent Cloud) como possível repositório de estágios adicionais. |

---

## 7. IoCs Consolidados

```
SHA256 (payload principal): 77e220b261fbfcc539ecab0d3567603ee3e261c02ad1a26c7ce19e513f240a4d
SHA256 (execution parent PE): bbc61f3eee2100bf32cee55ea7e221f020fa3bdb37adf51f2d49ec68e2733bae
SHA256 (execution parents ZIP):
44a11ca55c3bdc05f3cfa1b323944cefd0ca0982f0368fffd2aec4ce6676b9b1
65c8b786b209421b36de3e7d13218c9f0c67257aad2f7236afebe0a40b453fd3
301145570a82107eae808c99d6da1cf8e5b0addb11d6ce6d48577bd8c16f9a9a

SHA256 (DLLs maliciosas dropadas):
c1dbde75f6548c53c81d68855006e7d40673feb10c688dd1e31053205e19fd13
fa17cb6c2520bc6a68b759eed3c727cf21c7880984a2174ff4d3e159f9332dcc
2827f9b6576b43f16e1f963aeb6f1f6e1df195d66f269c071e804a96aaafbed9
7cb09c17cd73bc602513ff039fa95642416758f2680877c4d73768badb60852b

SHA256 (JavaScript relacionado): 00001f277697bab3cd2412d92a1926328eb8f864fdb27043e6f604cd748b594a

IP hub de distribuição: 27.124.18.166
IP hospedagem secundária: 43.132.105.206
IP comunicante do JavaScript: 92.223.96.6

Domínio suspeito (JavaScript): cl-glcb907925.gcdn.co
Domínio de armazenamento secundário: alidata-1327210346.cos.ap-hongkong.myqcloud.com
```

---

## 8. Recomendações

1. Bloquear o IP `27.124.18.166` nos controles de perímetro, já que atua como hub central de distribuição para múltiplos pacotes desta campanha.
2. Verificar a presença das 4 DLLs maliciosas listadas na seção 4.2 no ambiente monitorado.
3. Monitorar tráfego de saída para o domínio `cl-glcb907925.gcdn.co`, dado seu papel possível como canal de comando disfarçado.
4. Investigar isoladamente o repositório em `alidata-1327210346.cos.ap-hongkong.myqcloud.com`, pois pode hospedar estágios adicionais do payload.
5. Considerar o tráfego para domínios da GlobalSign e da Microsoft (seção 5.2) como ruído esperado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura ValleyRAT).
Coleções do VT Graph associadas ao indicador primário (DonutLoader e 银狐 / SilverFox).
