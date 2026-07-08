# Threat Intelligence Report: Abuso de ConnectWise ScreenConnect

**ID:** 05_2026-07_connectwise-screenconnect-abuse
**Data:** 08/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

Essa amostra difere das quatro anteriores em um ponto importante. A assinatura ConnectWise no MalwareBazaar não identifica uma família de malware tradicional, mas sim a instalação não autorizada do ConnectWise ScreenConnect, ferramenta legítima de acesso remoto amplamente usada por equipes de TI e igualmente abusada por operadores de acesso inicial para obter controle remoto persistente sobre a máquina da vítima, evitando assinaturas de malware convencionais por se apoiar em um binário assinado e confiável.

O grafo confirma esse padrão. O executável principal contata o domínio `subscription-magnetic-recommended-meat.trycloudflare.com`, um subdomínio do serviço gratuito de túneis do Cloudflare (TryCloudflare), técnica documentada em campanhas recentes de entrega do ScreenConnect por trás de páginas falsas de atualização de navegador ou verificações de captcha, prática conhecida como ClickFix. O uso do TryCloudflare permite ao operador expor um servidor de C2 sem precisar registrar domínio próprio ou manter infraestrutura fixa, já que o Cloudflare rotaciona o IP de borda automaticamente.

Entre os 20 arquivos dropados, destaca se um instalador MSI com detecção positiva, consistente com o pacote de instalação do ScreenConnect, além de 4 bibliotecas DLL também com detecção positiva. O MSI compartilha comunicação com um IP nos Estados Unidos que também aparece como referrer file, isto é, um endereço que serviu de origem para o download desse instalador, possivelmente parte da própria infraestrutura de distribuição do ScreenConnect explorada indevidamente.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `433b61c29aefaa5b55fe78063e6ad8597d3835f36e1242d5402ab23e6dc61194` |
| MD5 | `57d20ed65870aa249ca374142d763d13` |
| Nome do arquivo | `lirMkvpf.exe` |
| Tamanho | 7.168 bytes |
| Primeira submissão | 08/07/2026 13:26:03 UTC |
| Última submissão | 08/07/2026 13:26:08 UTC |
| Detecção | 7 vendors |
| Regras YARA associadas | 8 |

O tamanho reduzido do executável (7 KB) é consistente com um estágio inicial leve, cuja função provável é apenas orquestrar o download e a instalação do pacote ScreenConnect completo, não carregar a lógica de acesso remoto em si.

---

## 3. Bundled Files (4)

| SHA256 | Tipo | Observações |
|---|---|---|
| `920cbec0e219f5757e6d4b1bd60c4f9b7b23922ac1f33021f8756b4eac41c503` | Não informado | Sem detecção. |
| `c0085eb467d2fc9c9f395047e057183b3cd1503a4087d0db565161c13527a76f` | XML | Sem detecção. Provável arquivo de configuração do instalador. |
| `ccf44b21d1038411e2b42d79b40c147eccb3fa900d2ff9885dfbd7be20d183a1` | Não informado | Sem atributos no export. |
| `ed9008baebb1eb491c9e9374c473714d72d4bf061cb81e65faf676ba3b60c678` | Não informado | Sem atributos no export. |

---

## 4. Dropped Files (20)

| Tipo | Quantidade | Detecção positiva |
|---|---|---|
| PE DLL | 10 | 4 (`a45ba86c5d1...`, `b8100e5ab07...`, `da29455a648...`, mais 1 sem detecção individual entre as 10) |
| MSI | 3 | 1 (`8e87a734dad...`) |
| CSV | 2 | Nenhuma |
| XML | 1 | Nenhuma |
| PowerShell | 1 | Nenhuma |
| Sem atributos no export | 3 | Não informado |

O instalador MSI com detecção positiva é o componente central desta cadeia, já que corresponde ao pacote responsável por instalar o cliente ScreenConnect na máquina comprometida. O script PowerShell entre os dropped files também merece atenção direta, dado que ferramentas de acesso remoto costumam usar scripts desse tipo para automatizar a configuração silenciosa do cliente após a instalação.

---

## 5. Infraestrutura de Rede

### 5.1 Domínios contatados (2)

| Domínio | Observações |
|---|---|
| `subscription-magnetic-recommended-meat.trycloudflare.com` | Subdomínio de túnel gratuito do Cloudflare. Indicador mais relevante da investigação, associado a campanhas de entrega de ScreenConnect via páginas falsas de atualização ou verificação (ClickFix). |
| `api.msn.com` | Domínio legítimo da Microsoft. Provável ruído de telemetria do sistema operacional. |

### 5.2 IPs contatados (6)

| IP | País | Detecção | Observações |
|---|---|---|---|
| `104.16.231.132` | ZZ | Positiva | Faixa de borda do Cloudflare, associada ao túnel TryCloudflare contatado. |
| `207.174.0.143` | US | Positiva | Também aparece como referrer file do instalador MSI (seção 4), possível ponto de distribuição do pacote ScreenConnect. |
| `104.16.230.132` | ZZ | Nenhuma | Faixa de borda do Cloudflare, mesmo padrão do IP acima. |
| `199.232.214.172` | US | Nenhuma | Fastly CDN. |
| `1.1.1.1` | ZZ | Nenhuma | Resolver público Cloudflare, checagem de conectividade. |
| `8.8.8.8` | US | Nenhuma | Resolver público Google, checagem de conectividade. |

### 5.3 URL contatada

O grafo lista uma URL contatada pelo executável principal, sem o texto completo disponível no export atual. Recomenda se abrir o nó diretamente no VT Graph para obter o valor exato, já que provavelmente aponta para o endpoint de download do instalador dentro do túnel TryCloudflare.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Remote Access Software | T1219 | Uso do ConnectWise ScreenConnect como ferramenta de acesso remoto não autorizada. |
| Protocol Tunneling | T1572 | Uso do serviço TryCloudflare para expor infraestrutura de distribuição sem domínio ou IP fixo. |
| User Execution | T1204 | Padrão documentado da técnica ClickFix, que induz a vítima a executar o instalador manualmente através de uma falsa verificação. |
| Ingress Tool Transfer | T1105 | Download do pacote completo do ScreenConnect (MSI) a partir do executável inicial leve. |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Script PowerShell entre os dropped files, provável responsável pela configuração silenciosa do cliente remoto. |

---

## 7. IoCs Consolidados

```
SHA256 (executável inicial): 433b61c29aefaa5b55fe78063e6ad8597d3835f36e1242d5402ab23e6dc61194
SHA256 (instalador MSI): 8e87a734daddd95322b3f18f71eb9275219e244aac4f62b8dc6da6e2e91525e9

DLLs maliciosas dropadas:
a45ba86c5d13aa8e814e4cb0860b5b2a39ce9677b0d980947f6fe31676051cb2
b8100e5ab07983cbf82d721cf719576ca3f60e352628dcaabd42d428011fdedf
da29455a64858fda773319c32c0a6cd40edbe8042ed005aa2befb8a4f0fb0522

Domínio de distribuição: subscription-magnetic-recommended-meat.trycloudflare.com
IP de referência do instalador: 207.174.0.143
```

---

## 8. Recomendações

1. Bloquear o subdomínio TryCloudflare listado acima e monitorar novos subdomínios sob `trycloudflare.com` no tráfego de saída, já que esses nomes são gerados dinamicamente a cada nova sessão de túnel.
2. Verificar se o ConnectWise ScreenConnect está instalado de forma autorizada no ambiente. Caso não esteja entre as ferramentas de RMM aprovadas pela organização, tratar a presença do MSI listado como indicador direto de comprometimento.
3. Auditar o script PowerShell dropado, priorizando a checagem de parâmetros de configuração silenciosa que possam indicar o servidor de relay usado pelo operador.
4. Investigar isoladamente o IP `207.174.0.143`, dado seu papel como referrer do instalador.
5. Considerar o tráfego para `api.msn.com` e para os resolvedores públicos como ruído esperado do sistema operacional, sem necessidade de bloqueio.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura ConnectWise).
