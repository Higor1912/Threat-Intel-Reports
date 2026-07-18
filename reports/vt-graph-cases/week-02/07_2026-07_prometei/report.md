# Threat Intelligence Report: Prometei

**ID:** week-02/07_2026-07_prometei
**Data:** 18/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Prometei via assinatura no MalwareBazaar, com 8 detecções entre vendors e 4 regras YARA associadas. Prometei é um botnet modular conhecido por combinar mineração de criptomoeda, coleta de credenciais e propagação semi autônoma através de exploração de vulnerabilidades conhecidas e força bruta contra serviços expostos, historicamente documentado desde 2020.

Antes de detalhar a infraestrutura, vale uma nota metodológica importante. Dos 8 domínios contatados pela amostra, todos os 8 correspondem a serviços padrão do ecossistema Ubuntu e GNOME: Snapcraft, atualização de firmware, extensões do GNOME, mensagem do dia e um servidor raiz DNS. Nenhum apresenta detecção positiva. Esse é um padrão já visto na investigação de Mirai na primeira semana desta série, e reforça a mesma conclusão: esse tráfego provavelmente reflete o comportamento padrão do próprio sistema operacional Linux usado no sandbox de análise dinâmica, não comportamento malicioso da amostra. Vale registrar como aprendizado recorrente para próximas investigações de amostras ELF.

A infraestrutura de rede realmente relevante aparece na lista de IPs contatados. Um bloco de 7 endereços na faixa `185.125.188.0/24`, no Reino Unido, tem 6 deles com detecção positiva, e esse mesmo bloco já havia aparecido na investigação de Mirai da semana anterior desta série, com sobreposição direta de 6 endereços idênticos. Essa é a segunda correlação de infraestrutura compartilhada entre semanas diferentes desta série, depois da encontrada entre ValleyRAT e ScarfaceStealer, e reforça que esse bloco específico no Reino Unido funciona como infraestrutura compartilhada entre famílias completamente diferentes, um worm de IoT em um caso e um botnet de mineração em outro. Um IP no Vietnã também aparece com detecção positiva, isolado do restante do padrão observado.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | ELF |
| SHA256 | `87e7393996e5c578b05e9a2b6e128bc3c71a98c8b615eb48a2b87d5f47fcea1b` |
| MD5 | `3c58e6df8e9b44c825bcd18722b4033c` |
| Tamanho | 449.080 bytes |
| Primeira submissão | 18/07/2026 09:41:38 UTC |
| Detecção | 8 vendors |
| Regras YARA associadas | 4 |

---

## 3. Dropped Files (9)

A amostra aparece como seu próprio execution parent e como um dos dropped files, padrão de autorreplicação consistente com o comportamento documentado de worm da família Prometei.

| SHA256 | Tipo | Detecção | Observações |
|---|---|---|---|
| `c655d3d4e374fad38313ec4262207b2d7d68a870238f203ef3c33f85e66c8e32` | INI | Positiva | Provável arquivo de configuração do módulo, coerente com a arquitetura modular da família. |
| `7923929750438220ee95d198441ec661a3af7667587f9a3d23a666f932cb4731` | Texto | Nenhuma | |
| `c1310def6cff34770cb8bcd4dabdca2a0b5effc1bf1a99a867515808b29b33b0` | Texto | Nenhuma | |
| Demais 5 arquivos | Não informado | Sem atributos no export | |

---

## 4. Nota Metodológica: Ruído de Sandbox em Amostras ELF

Os 8 domínios contatados por esta amostra (`api.snapcraft.io`, `dashboard.snapcraft.io`, `cdn.fwupd.org`, `extensions.gnome.org`, `odrs.gnome.org`, `ingress.openshift.gnome.org`, `motd.ubuntu.com`, `c.root-servers.net`) são todos serviços legítimos do ecossistema Ubuntu Desktop e GNOME, sem exceção, e nenhum tem detecção positiva. O domínio `api.snapcraft.io` em particular já havia aparecido exatamente na mesma função na investigação de Mirai, primeira semana desta série. A repetição desse padrão específico em duas amostras ELF distintas, de famílias diferentes, é um indício forte de que essa lista reflete o ambiente de sandbox Linux usado pelo VirusTotal para execução dinâmica, não comportamento de rede da própria amostra. Fica registrado como critério de triagem para próximas investigações: domínios do Ubuntu/GNOME em amostras ELF devem ser tratados como ruído de ambiente por padrão, a menos que apareçam com detecção positiva.

---

## 5. Infraestrutura de Rede Relevante

### 5.1 Bloco compartilhado com a investigação de Mirai: 185.125.188.0/24 (Reino Unido)

| IP | Detecção | Observações |
|---|---|---|
| `185.125.188.54` | Nenhuma | Também presente na investigação de Mirai (semana 1). |
| `185.125.188.55` | Positiva | Também presente na investigação de Mirai (semana 1). |
| `185.125.188.57` | Positiva | Também presente na investigação de Mirai (semana 1). |
| `185.125.188.58` | Positiva | Também presente na investigação de Mirai (semana 1). |
| `185.125.188.59` | Positiva | Também presente na investigação de Mirai (semana 1). |
| `185.125.188.60` | Positiva | Também presente na investigação de Mirai (semana 1). |
| `185.125.188.61` | Positiva | Endereço adicional, não presente na lista da investigação de Mirai. |
| `185.125.188.62` | Positiva | Endereço adicional, não presente na lista da investigação de Mirai. |

Seis dos oito endereços deste bloco coincidem exatamente com os identificados na investigação de Mirai da semana anterior desta série. Esse é o segundo caso de infraestrutura compartilhada confirmada entre famílias diferentes ao longo da série, reforçando que esse bloco no Reino Unido funciona como hospedagem reaproveitada entre operadores ou campanhas distintas.

### 5.2 Outros IPs com detecção positiva

| IP | País | Observações |
|---|---|---|
| `103.176.111.176` | VN | Isolado do restante do padrão, sem correlação com outras amostras desta série até o momento. |

### 5.3 Infraestrutura sem detecção, provável ruído

O restante dos 24 IPs contatados corresponde a faixas da Fastly CDN (Estados Unidos), Amazon Web Services na Irlanda, e alguns endereços na Itália sem contexto claro, nenhum com detecção positiva. Tratados como prováveis espelhos de download de pacotes ou telemetria padrão do sistema.

### 5.4 URLs Contatadas

3 das 6 URLs listadas têm detecção positiva, mas nenhuma trouxe texto completo no export atual. Recomenda se abrir cada nó diretamente no VT Graph para obter os valores exatos.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Resource Hijacking | T1496 | Comportamento central e documentado da família Prometei, voltado a mineração de criptomoeda. |
| Exploitation of Remote Services | T1210 | Padrão histórico de propagação da família via exploração de serviços expostos. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o bloco de IPs no Reino Unido e com as URLs flagged. |
| Web Service | T1102 | Reaproveitamento confirmado do mesmo bloco de IPs por uma família diferente na semana anterior desta série. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): 87e7393996e5c578b05e9a2b6e128bc3c71a98c8b615eb48a2b87d5f47fcea1b
SHA256 (arquivo de configuração INI): c655d3d4e374fad38313ec4262207b2d7d68a870238f203ef3c33f85e66c8e32

Bloco de IPs compartilhado com investigação de Mirai:
185.125.188.55
185.125.188.57
185.125.188.58
185.125.188.59
185.125.188.60
185.125.188.61
185.125.188.62

IP isolado: 103.176.111.176
```

---

## 8. Recomendações

1. Bloquear o bloco `185.125.188.0/24` nos controles de perímetro, já confirmado como infraestrutura reaproveitada entre duas famílias distintas nesta série.
2. Investigar o IP vietnamita isoladamente, dado que não apresenta correlação com outras amostras já analisadas.
3. Abrir diretamente no VT Graph as 3 URLs com detecção positiva para obter o texto completo, já que provavelmente revelam o endpoint específico de callback do módulo de configuração.
4. Aplicar o critério estabelecido na seção 4 para triagem de futuras amostras ELF, tratando domínios Ubuntu/GNOME como ruído de sandbox por padrão.
5. Considerar o tráfego para Fastly CDN e AWS Irlanda como ruído esperado, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Prometei).
Correlação cruzada com o relatório 01_2026-07_mirai-elf-variant (semana 1) desta mesma série.
