# Threat Intelligence Report: WannaCry

**ID:** week-02/01_2026-07_wannacry
**Data:** 12/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como WannaCry via assinatura no MalwareBazaar, com 11 detecções entre vendors e 4 regras YARA associadas. O achado central desta investigação não está na amostra em si, mas no que o grafo revela sobre como ela continua circulando quase uma década depois do surto original de 2017.

O indicador primário é a própria DLL de criptografia do WannaCry, sem contato direto de rede próprio. Isso já era esperado, já que esse componente historicamente depende do módulo de propagação via EternalBlue para se espalhar, não de comunicação direta com C2. O que chama atenção é a lista de 20 execution parents distintos, quase todos executáveis PE com detecção positiva, além de um ZIP e um script shell. Ou seja, o mesmo payload de criptografia do WannaCry está sendo reempacotado e distribuído por pelo menos 20 cadeias de infecção diferentes, cada uma com sua própria infraestrutura de entrega.

Ao rastrear a origem de cada uma dessas 20 cadeias, aparecem três padrões de distribuição distintos. Uma delas contata o Google Drive diretamente, provável abuso de armazenamento legítimo para hospedar o pacote completo. Outra contata `users.qzone.qq.com`, rede social chinesa, em um padrão que lembra a técnica de dead drop resolver já vista na investigação de QuasarRAT na semana anterior. Uma terceira contata um domínio `.ru` com nome aleatório e detecção positiva, infraestrutura de comando mais tradicional. O restante das 20 cadeias não foi individualmente rastreado neste relatório, mas fica registrado como próximo passo.

Esse padrão reforça um ponto relevante para times de defesa: o payload do WannaCry não precisa mais do EternalBlue para continuar sendo um problema. Operadores atuais parecem estar reaproveitando o módulo de criptografia original como carga útil dentro de cadeias de infecção completamente novas e não relacionadas entre si.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE DLL |
| SHA256 | `3d00cff108f59b705efcdba34bf429142b95170e6e876093609a1b44d8ae7fe9` |
| MD5 | `2eb8f13afb5adc3b92034da6311dd700` |
| Tamanho | 5.298.176 bytes |
| Primeira submissão | 12/07/2026 16:15:19 UTC |
| Detecção | 11 vendors |
| Regras YARA associadas | 4 |

---

## 3. Bundled Files (2)

| SHA256 | Observações |
|---|---|
| `6cf1b57d59e7111bc218dfb01dda93ac0f776715599a1c69f89035bd20c16a10` | Contata 6 URLs sem texto disponível no export atual, detalhado na seção 4. |
| `f7b74bf682e6dc378bb1b90a5064ec9827a2e23e4e4781b7f9a5bc183b0a3eea` | Aparece como o nó central dos 20 execution parents detalhados na seção 5. |

---

## 4. URLs Contatadas (6)

O primeiro bundled file contata 6 URLs, nenhuma com texto completo disponível no export atual, e nenhuma com detecção positiva isolada. Recomenda se abrir cada nó diretamente no VT Graph para obter os valores exatos.

---

## 5. Execution Parents (20)

| Composição | Quantidade |
|---|---|
| PE EXE com detecção positiva | 17 |
| ZIP com detecção positiva | 1 |
| ZIP sem detecção | 1 |
| Shell script sem detecção | 1 |

Três desses execution parents tiveram sua infraestrutura de rede rastreada nesta rodada.

### 5.1 Cadeia via Google Drive

O execution parent `1d65adf3d53d2e6a7967de17f625d0556f0821958816637c60f76940e4c28520` contata `drive.google.com` diretamente. Um segundo execution parent, `180fa31945894564986e14aab475e092ba0a1aa9c729c8a8b9efe36a1499f5ce`, também contata o Google Drive além do domínio detalhado a seguir, sugerindo que essa cadeia usa armazenamento legítimo do Google para hospedar o pacote completo antes de liberar o payload do WannaCry.

### 5.2 Cadeia via domínio russo com detecção positiva

O mesmo execution parent `180fa319...` contata `hgfajdgvbxc.ru`, domínio de nome aleatório com detecção positiva no VT, o indicador de rede mais direto encontrado nesta investigação.

### 5.3 Cadeia via QQ Zone

O execution parent `29be0f5115afa4d678646cfe90dbfbfcd9386a46482954d83ea2faff21349b34` contata `users.qzone.qq.com`, rede social chinesa, também com detecção positiva. O padrão lembra a técnica de dead drop resolver documentada na investigação de QuasarRAT da semana anterior, na qual uma página pública é usada para resolver dinamicamente informações de comando, embora aqui a confirmação completa do mecanismo exija análise adicional do conteúdo da página em si.

### 5.4 Demais 17 execution parents

Não foram individualmente expandidos nesta rodada. Ficam registrados como pendência para uma investigação de acompanhamento, já que cada um representa potencialmente uma cadeia de distribuição própria.

---

## 6. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Ingress Tool Transfer | T1105 | Reempacotamento do payload de criptografia original em ao menos 20 cadeias de distribuição distintas. |
| Web Service | T1102 | Uso do Google Drive como hospedagem de pacote completo em pelo menos uma das cadeias rastreadas. |
| Dead Drop Resolver | T1102.001 | Padrão de contato com página pública (QQ Zone) observado em uma das cadeias, pendente de confirmação completa. |
| Data Encrypted for Impact | T1486 | Comportamento histórico e confirmado da família WannaCry como payload de criptografia. |

---

## 7. IoCs Consolidados

```
SHA256 (payload de criptografia WannaCry): 3d00cff108f59b705efcdba34bf429142b95170e6e876093609a1b44d8ae7fe9

Execution parents com infraestrutura rastreada:
1d65adf3d53d2e6a7967de17f625d0556f0821958816637c60f76940e4c28520 (Google Drive)
180fa31945894564986e14aab475e092ba0a1aa9c729c8a8b9efe36a1499f5ce (Google Drive + domínio russo)
29be0f5115afa4d678646cfe90dbfbfcd9386a46482954d83ea2faff21349b34 (QQ Zone)

Domínio malicioso confirmado: hgfajdgvbxc.ru
```

---

## 8. Recomendações

1. Bloquear o domínio `hgfajdgvbxc.ru` nos controles de perímetro.
2. Monitorar downloads de arquivos executáveis a partir de links do Google Drive, prática cada vez mais comum como camada de distribuição legítima disfarçada.
3. Expandir individualmente os 17 execution parents ainda não rastreados nesta rodada, priorizando os que apresentam detecção positiva própria.
4. Verificar a presença do payload de criptografia original em qualquer um dos hosts que tenham baixado arquivos das cadeias identificadas, já que a execução final continua sendo ransomware independente da via de entrega.
5. Tratar essa amostra como lembrete de que a atribuição de família por assinatura não garante que o vetor de infecção seja o mesmo do surto histórico original, o payload pode estar sendo reciclado por operadores completamente diferentes.

---

## 9. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura WannaCry).
