# Threat Intelligence Report: ScarfaceStealer

**ID:** week-02/04_2026-07_scarfacestealer
**Data:** 15/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como ScarfaceStealer via assinatura no MalwareBazaar, com 8 detecções entre vendors. O nome do arquivo, `installer.exe`, e o tamanho de 90 MB, muito acima do padrão até para um dropper, sugerem um pacote inflado deliberadamente, técnica comum para dificultar análise em sandboxes com limite de tamanho de upload ou para acomodar recursos legítimos que servem de disfarce.

O achado central desta investigação é, de longe, o maior padrão de reaproveitamento de componente observado em toda a série até agora. A cadeia começa com o executável principal, que tem como execution parent um arquivo ZIP. Esse ZIP bundla e dropa uma DLL específica, e essa DLL, por sua vez, aparece como execution parent de 125 outros arquivos distintos no grafo, sendo 88 executáveis PE, 36 arquivos ZIP e 1 RAR, com 73 desses 125 já carregando detecção positiva própria. Isso indica que essa DLL não é exclusiva desta campanha. Ela funciona como um componente central compartilhado, muito provavelmente parte de um builder ou serviço de crypter usado por múltiplos operadores ou afiliados para empacotar payloads completamente diferentes.

Um segundo ponto reforça essa hipótese de infraestrutura compartilhada além desta campanha isolada. O executável principal contata o domínio `cl-glcb907925.globalcdn.co`, praticamente idêntico ao domínio `cl-glcb907925.gcdn.co` identificado na investigação de ValleyRAT na semana anterior desta série, mudando apenas o sufixo do provedor de CDN. O mesmo padrão se repete com o IP `92.223.96.6`, também presente naquela investigação anterior. Essa coincidência de indicadores entre duas campanhas de famílias diferentes, em semanas diferentes, é um sinal forte de que ambas se apoiam na mesma infraestrutura de terceiros, possivelmente o mesmo provedor de builder, crypter ou serviço de distribuição usado por diferentes clientes.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `1c779b7ae8a6e781242c7853e8d809255b8eb0cd598f63a20a5dcc3fe8e104db` |
| MD5 | `91ea5ad1a386bf675fc972b879f5638f` |
| Nome do arquivo | `installer.exe` |
| Tamanho | 90.246.144 bytes |
| Primeira submissão | 15/07/2026 09:45:26 UTC |
| Detecção | 8 vendors |

---

## 3. Cadeia de Distribuição

| SHA256 | Tipo | Papel na cadeia |
|---|---|---|
| `f66ca8681b33a68660880a4364cd956c0c8e6e7706970cc31969d4a045de42ed` | ZIP | Execution parent do executável principal. Bundla e dropa a DLL compartilhada abaixo. |
| `c333d919fe031760275cb37d9b82d509a5da2ad82888fe13ea667ae388c2946b` | PE DLL | Componente central compartilhado, detalhado na seção 4. |
| `5ec45e76cf6e36f17a7bee5978746e5595fbe0ce265d6fb935848799ef99ec67` | PE DLL | Bundled/dropped pelo mesmo ZIP, sem detecção. |
| `2a6a0519a1b4470751a7db17fbc9f46229baff32db37ef571fcd36d2a42f434b` | PE DLL | Bundled/dropped pelo mesmo ZIP, sem detecção. |

O executável principal também carrega 22 bundled files próprios, majoritariamente sem atributos detalhados no export atual, entre eles uma imagem ISO e um XML de configuração.

---

## 4. Componente Compartilhado: DLL com 125 Execution Parents

Essa DLL é o achado mais relevante da investigação. Ela aparece como execution parent de 125 arquivos distintos no grafo, muito acima de qualquer padrão de reaproveitamento visto até agora nesta série.

| Composição | Quantidade | Com detecção positiva |
|---|---|---|
| PE EXE | 88 | Maioria |
| ZIP | 36 | Maioria |
| RAR | 1 | Sim |
| **Total** | **125** | **73** |

Um volume dessa magnitude não é compatível com uma campanha isolada. É mais consistente com um componente técnico reutilizado por múltiplos operadores a partir da mesma fonte, como um crypter, packer ou builder comercializado ou compartilhado em fóruns, onde diferentes atores geram payloads distintos a partir do mesmo núcleo de código.

---

## 5. Infraestrutura de Rede

### 5.1 Domínios contatados pelo executável principal (2)

| Domínio | Observações |
|---|---|
| `cl-glcb907925.globalcdn.co` | Praticamente idêntico ao domínio `cl-glcb907925.gcdn.co` identificado na investigação de ValleyRAT (semana 1, relatório 03), mudando apenas o sufixo de CDN. Forte indício de infraestrutura compartilhada entre campanhas de famílias diferentes. |
| `a1672.dscr.akamai.net` | Faixa Akamai, provável ruído de CDN legítima. |

### 5.2 IPs contatados pelo executável principal (4)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `92.223.96.6` | US | Positiva | Mesmo IP identificado na investigação de ValleyRAT (semana 1), reforçando a hipótese de infraestrutura compartilhada entre campanhas. |
| `162.159.36.2` | ZZ | Nenhuma | Faixa Cloudflare. |
| `23.195.81.59`, `23.195.81.73` | US | Nenhuma | Faixa Akamai. |

### 5.3 Infraestrutura contatada pelo ZIP execution parent

O ZIP contata separadamente um pequeno bloco de IPs na faixa `150.171.x.x`, associada a servidores de saída de email da Microsoft, e domínios legítimos da Microsoft e DigiCert, prováveis ruído de verificação de certificado e telemetria do sistema.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Obfuscated Files or Information | T1027 | Tamanho inflado do executável principal (90 MB), técnica de evasão contra sandboxes com limite de upload. |
| Ingress Tool Transfer | T1105 | Cadeia de distribuição via ZIP contendo o componente DLL compartilhado. |
| Web Service | T1102 | Reaproveitamento confirmado de domínio e IP já vistos em campanha de família diferente na semana anterior desta série. |
| Masquerading | T1036 | Nome de arquivo genérico (`installer.exe`) típico de campanhas de distribuição via sites falsos de download. |

---

## 7. IoCs Consolidados

```
SHA256 (executável principal): 1c779b7ae8a6e781242c7853e8d809255b8eb0cd598f63a20a5dcc3fe8e104db
SHA256 (ZIP execution parent): f66ca8681b33a68660880a4364cd956c0c8e6e7706970cc31969d4a045de42ed
SHA256 (DLL compartilhada, 125 execution parents): c333d919fe031760275cb37d9b82d509a5da2ad82888fe13ea667ae388c2946b

Domínio compartilhado entre campanhas: cl-glcb907925.globalcdn.co
IP compartilhado entre campanhas: 92.223.96.6
```

---

## 8. Recomendações

1. Tratar a DLL `c333d919...` como indicador de alta prioridade para hunting, dado seu papel como componente compartilhado por 125 arquivos maliciosos distintos.
2. Correlacionar esta investigação com o relatório de ValleyRAT da semana anterior, já que ambos compartilham o mesmo IP e um padrão quase idêntico de domínio de CDN, possível indício de uma infraestrutura comum de distribuição usada por operadores diferentes.
3. Investigar uma amostra representativa dos 125 execution parents identificados para confirmar se todos derivam do mesmo builder ou apenas compartilham o mesmo crypter comercial.
4. Sinalizar arquivos chamados genericamente `installer.exe` com tamanho muito acima do esperado como indicador comportamental de triagem.
5. Considerar o tráfego para a faixa `150.171.x.x` e domínios da Microsoft e DigiCert como ruído esperado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura ScarfaceStealer).
Correlação cruzada com o relatório 03_2026-07_valleyrat (semana 1) desta mesma série.
