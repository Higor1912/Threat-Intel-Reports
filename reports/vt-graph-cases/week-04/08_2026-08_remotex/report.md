# Threat Intelligence Report: RemoteX

**ID:** week-04/08_2026-08_remotex
**Data:** 01/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como RemoteX via assinatura no MalwareBazaar, com 6 detecções entre vendors e 6 regras YARA associadas. O nome do arquivo veio genérico (`file`), e o contato de rede direto do executável principal é mínimo: um único domínio com nome longo e aleatório, sem detecção, e um único IP da faixa Cloudflare.

A riqueza real desta investigação está nos 6 dropped files do tipo DLL, todos sem detecção individual, mas cada um funcionando de forma independente como execution parent de aproximadamente 20 outros arquivos no grafo, majoritariamente executáveis PE e alguns ZIP, com a maioria já carregando detecção positiva própria. Esse padrão de seis componentes de biblioteca compartilhados simultaneamente, cada um com seu próprio conjunto de reaproveitamento, é a assinatura mais consistente com um pacote de runtime ou toolkit de terceiros distribuído em conjunto, reforçando um tema que já apareceu repetidamente nesta série: componentes técnicos genéricos acabam funcionando como pontes entre campanhas de famílias diferentes.

Um dos arquivos que aparece como execution parent de uma dessas DLLs revelou, por sua vez, seu próprio conjunto de 20 domínios e 20 IPs contatados, majoritariamente infraestrutura legítima de publicidade e telemetria (Bing, Google, GlobalSign), com uma exceção: o domínio `absba.cc`, já com detecção positiva.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `5f76fc369f3f759a64fe0770294a303c918c1dca5af021ba9ea0bbc7ab2559f6` |
| MD5 | `658cb87887c1aa843e39aea3aab26073` |
| Nome do arquivo | `file` (nome genérico) |
| Tamanho | 17.833.552 bytes |
| Primeira submissão | 01/08/2026 04:43:54 UTC |
| Detecção | 6 vendors |
| Regras YARA associadas | 6 |

---

## 3. Infraestrutura de Rede Direta

| Indicador | Detecção | Observações |
|---|---|---|
| `srosyckczcxcrjrvbkxavonoqx23sphq3eaxxlgqzlijufeqyz.com` | Nenhuma | Nome longo e aleatório, padrão sugestivo de DGA, mesmo sem detecção confirmada ainda. |
| `162.159.36.2` | Nenhuma | Faixa Cloudflare. |

---

## 4. Dropped Files: Seis Bibliotecas Amplamente Reaproveitadas

| SHA256 | Tipo | Detecção própria | Execution parents (amostra de 20) |
|---|---|---|---|
| `60244935dea2bfde43278b14c29ca3f909518c4422a12dacd587896be692f535` | PE DLL | Nenhuma | 16 PE EXE, 3 ZIP, majoritariamente com detecção positiva |
| `a68a9ac35aa1e183fe3bd9e7144259631530db07502112a339e5e1c8dccc9a31` | PE DLL | Nenhuma | 20 arquivos adicionais |
| `a62f73b7cef738ebd9963744665aa85772b428aef214f07f8112ff3816b09241` | PE DLL | Nenhuma | 20 arquivos adicionais |
| `e30874ceaf6b8dfe72ba67e5c1f21027d79cb3a873a32eb12c5ed89bfa660d1f` | PE DLL | Nenhuma | 20 arquivos adicionais |
| `2728e26af764a64dd31f6df20bad9ce68f27a1c54628abf7353a62f5e67a9dff` | PE EXE | Nenhuma | 20 arquivos adicionais |
| `5dc711b1f190df5b1257b92883e9c3f10cb4e953591da13dd50d9f0c7a4af695` | PE DLL | Nenhuma | 20 arquivos adicionais |

O grafo limita a exibição de cada relação a 20 itens, então o número real de reaproveitamento por componente é provavelmente maior. Ainda assim, seis componentes distintos, cada um funcionando como estágio para dezenas de outros arquivos, é uma escala de compartilhamento comparável à do ícone do Formbook (semana 3) e à da DLL do ScarfaceStealer (semana 2).

### 4.1 Nó Secundário com Infraestrutura Própria

Um dos 20 execution parents da primeira DLL (`0902aea5608e5f2b3227ced2fa21f00e3dc4d098788d191f438eb4ac64814161`) tem seu próprio conjunto de 20 domínios e 20 IPs contatados. A composição é majoritariamente infraestrutura legítima de publicidade e telemetria: Bing, Google, fontes do Google, GlobalSign, Telegram CDN. O único domínio com detecção positiva nesse conjunto é `absba.cc`.

---

## 5. Outros Dropped Files

| SHA256 | Tipo | Detecção |
|---|---|---|
| `11f4793ab3b74ef8f5c38bda02bfe18282baadf421402a32cb055d1affca0b5e` | PE EXE | Positiva |
| Demais 4 arquivos | Não informado | Sem atributos no export |

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Dynamic Resolution | T1568 | Domínio de C2 com nome longo e aleatório, padrão sugestivo de DGA. |
| Ingress Tool Transfer | T1105 | Seis bibliotecas DLL dropadas, cada uma reaproveitada como estágio por dezenas de arquivos adicionais. |
| Web Service | T1102 | Infraestrutura de publicidade e telemetria legítima contatada pelo nó secundário, possível camuflagem de tráfego. |

---

## 7. IoCs Consolidados

```
SHA256 (amostra principal): 5f76fc369f3f759a64fe0770294a303c918c1dca5af021ba9ea0bbc7ab2559f6

SHA256 (bibliotecas compartilhadas):
60244935dea2bfde43278b14c29ca3f909518c4422a12dacd587896be692f535
a68a9ac35aa1e183fe3bd9e7144259631530db07502112a339e5e1c8dccc9a31
a62f73b7cef738ebd9963744665aa85772b428aef214f07f8112ff3816b09241
e30874ceaf6b8dfe72ba67e5c1f21027d79cb3a873a32eb12c5ed89bfa660d1f
2728e26af764a64dd31f6df20bad9ce68f27a1c54628abf7353a62f5e67a9dff
5dc711b1f190df5b1257b92883e9c3f10cb4e953591da13dd50d9f0c7a4af695

Domínio suspeito adicional: absba.cc
```

---

## 8. Recomendações

1. Priorizar as seis DLLs listadas como indicadores de hunting de alto valor, dado o volume de reaproveitamento confirmado em cada uma.
2. Investigar uma amostra representativa dos arquivos que reaproveitam essas bibliotecas para confirmar se pertencem à mesma campanha ou a operadores diferentes usando o mesmo toolkit.
3. Bloquear o domínio `absba.cc` nos controles de perímetro.
4. Monitorar domínios com padrão de nome longo e aleatório como `srosyckczcxcrjrvbkxavonoqx23sphq3eaxxlgqzlijufeqyz.com`, mesmo sem detecção confirmada, como possível indicador de DGA ainda não catalogado.
5. Expandir manualmente os 4 dropped files sem atributos remanescentes diretamente no VT Graph.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura RemoteX).
