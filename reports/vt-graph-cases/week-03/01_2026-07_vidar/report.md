# Threat Intelligence Report: Vidar

**ID:** week-03/01_2026-07_vidar
**Data:** 19/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Vidar via assinatura no MalwareBazaar, com 9 detecções entre vendors e 9 regras YARA associadas. Vidar é um fork direto do ArkeiStealer, família já investigada na primeira semana desta série, e compartilha boa parte da arquitetura e do comportamento documentado daquela linhagem.

O nome do arquivo, `EclipseV2.exe`, e o tamanho de 71 MB seguem o mesmo padrão de inflação deliberada já visto no ScarfaceStealer da semana anterior, técnica usada para dificultar análise em sandboxes com limite de upload. Diferente da maioria das amostras desta série, porém, o executável principal em si tem uma pegada de rede direta bastante enxuta: apenas um IP da faixa Cloudflare, sem domínio contatado diretamente.

O grafo se expande de forma significativa a partir de uma das DLLs bundled, mas essa expansão trouxe um resultado que vale registrar com cautela. Essa DLL aparece referenciada em 20 coleções públicas distintas da comunidade VT, cobrindo temas completamente desconexos entre si, desde campanhas de malvertising até exploração da CVE-2023-22518 no Confluence, passando por golpes de Discord disfarçados de jogos e uma campanha de mods falsos para GTA5/FiveM. Nenhum dos IPs ou domínios que essa DLL contata diretamente apresenta detecção positiva, e os "domínios" listados são, na verdade, entradas de resolução reversa de DNS contra um bloco de IPs do Microsoft Azure. A leitura mais provável é que essa DLL seja um componente genérico e amplamente compartilhado, possivelmente um stub de empacotamento ou runtime reaproveitado por dezenas de campanhas não relacionadas, não uma peça de infraestrutura dedicada a esta campanha específica de Vidar. Registrar isso com essa ressalva é mais correto do que apresentar essa lista de coleções como evidência de campanha.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `3db0f2fa8d2225a0c3ad35c137e05370f846995750712259dca3a2dd00020c43` |
| MD5 | `2effc13d1714796ff13b06ebcd9125d0` |
| Nome do arquivo | `EclipseV2.exe` |
| Tamanho | 71.382.139 bytes |
| Primeira submissão | 19/07/2026 10:37:17 UTC |
| Detecção | 9 vendors |
| Regras YARA associadas | 9 |

---

## 3. Bundled Files e Dropped Files do Executável Principal

| SHA256 | Tipo | Observações |
|---|---|---|
| `3eb38ae99653a7dbc724132ee240f6e5c4af4bfe7c01d31d23faf373f9f2eaca` | PE DLL | Sem relações adicionais no export. |
| `b393f05e8ff919ef071181050e1873c9a776e1a0ae8329aefff7007d0cadf592` | PE DLL | Atua como execution parent próprio, com dropped files e contatos de rede não detalhados nesta rodada. |
| `b72e9013a6204e9f01076dc38dabbf30870d44dfc66962adbf73619d4331601e` | PE DLL | Componente genérico amplamente compartilhado, detalhado na seção 4. |
| `b57af73eccb51f420f180857e161968aa456c72773a72cb2eb0cb54134e80826` | 7zip | Sem relações adicionais no export. |

O executável principal também dropa um script PowerShell e um CSV, ambos sem detecção individual e sem relações adicionais no grafo.

---

## 4. Componente Genérico Compartilhado (DLL com 20 Coleções Públicas)

Essa DLL contata 15 IPs e 20 entradas de resolução reversa de DNS, nenhum com detecção positiva. Os IPs pertencem majoritariamente à infraestrutura de nuvem da Microsoft Azure (faixas `20.190.155.x` e `13.6x.x.x`), consistente com checagem de ambiente ou validação de certificado contra serviços da Microsoft, possivelmente uma técnica de fingerprinting para detectar se a execução está ocorrendo em ambiente de nuvem ou sandbox.

O ponto mais chamativo são as 20 coleções públicas da comunidade VT que referenciam esse hash, cobrindo campanhas completamente distintas:

| Coleção (nome original) | Tema |
|---|---|
| Malware distributed in internet ads (malvertising) | Distribuição via anúncios maliciosos |
| CVE-2023-22518 \| Confluence | Exploração de vulnerabilidade em Confluence |
| Recipe Lister - Lister.exe - Possibly Electron Infostealer | Infostealer baseado em Electron |
| Discord / Credential stealers mimicking games | Stealers disfarçados de jogos no Discord |
| TamperedChef campaign - GTA5/FiveM Mods variant | Mods falsos para GTA5/FiveM |
| Lunar Client | Cliente de Minecraft modificado |
| 5kplayer.zip exe apk dmg etc uac.dll malicious iOS/mac viewer | Player de mídia falso multiplataforma |
| www.icioud.live | Phishing temático de iCloud |

A dispersão temática dessas coleções é o próprio indício de que essa DLL não pertence a nenhuma campanha específica. É mais consistente com um componente técnico comum, como um stub de empacotamento, runtime compartilhado ou biblioteca de terceiros reaproveitada, que acaba sendo capturado junto de amostras completamente diferentes por coincidência de reuso de código, não por vínculo de infraestrutura.

---

## 5. Infraestrutura de Rede Direta da Amostra Principal

| Indicador | Detecção | Observações |
|---|---|---|
| `162.159.36.2` | Nenhuma | Faixa Cloudflare, único contato de rede direto do executável principal. |

A ausência de domínio ou IP malicioso contatado diretamente pelo executável raiz reforça a hipótese de que a lógica de exfiltração e comunicação com o C2 real do Vidar está concentrada em um dos componentes ainda não expandidos nesta rodada (`b393f05e...`, que já aparece como execution parent próprio mas não foi detalhado neste export).

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Obfuscated Files or Information | T1027 | Tamanho inflado do executável principal (71 MB), mesmo padrão observado no ScarfaceStealer da semana anterior. |
| Virtualization/Sandbox Evasion | T1497 | Padrão de resolução reversa de DNS contra infraestrutura Microsoft Azure, possível checagem de ambiente de nuvem ou sandbox. |
| Credentials from Password Stores | T1555 | Comportamento característico e documentado da família Vidar, herdado do ArkeiStealer. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): 3db0f2fa8d2225a0c3ad35c137e05370f846995750712259dca3a2dd00020c43
SHA256 (DLL execution parent própria, pendente de expansão): b393f05e8ff919ef071181050e1873c9a776e1a0ae8329aefff7007d0cadf592
SHA256 (DLL genérica compartilhada, tratar como componente não dedicado): b72e9013a6204e9f01076dc38dabbf30870d44dfc66962adbf73619d4331601e
```

---

## 8. Recomendações

1. Expandir manualmente o nó `b393f05e...` diretamente no VT Graph, já que aparece como execution parent próprio e provavelmente concentra a infraestrutura de C2 real desta campanha, não capturada neste export.
2. Não tratar as 20 coleções listadas na seção 4 como evidência de campanha para esta investigação específica, dado o padrão disperso e não relacionado entre elas.
3. Sinalizar executáveis com tamanho muito acima do esperado (`EclipseV2.exe` com 71 MB) como indicador comportamental de triagem, mesmo padrão já recomendado para o ScarfaceStealer.
4. Investigar se o padrão de resolução reversa contra a faixa `20.190.155.x` do Azure se repete em outras amostras da família Vidar, para confirmar se é uma técnica de fingerprinting deliberada ou artefato de ambiente de análise.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Vidar).
