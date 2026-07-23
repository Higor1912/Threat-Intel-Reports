# Threat Intelligence Report: Amadey

**ID:** week-03/05_2026-07_amadey
**Data:** 23/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como Amadey via assinatura no MalwareBazaar, com 7 detecções entre vendors e 46 regras YARA associadas, o maior número de regras desta série até agora. Amadey é um loader modular vendido no modelo malware as a service, historicamente usado como primeiro estágio para entregar payloads adicionais conforme o cliente do serviço configura.

O nome do arquivo, `WF9(斩神专属).exe`, usa caracteres em chinês que remetem a um mod ou ferramenta de jogo ("exclusivo" combinado com um nome estilizado), consistente com o vetor de distribuição documentado para Amadey em sites de cheats e modificações de jogos voltados ao público chinês.

O grafo confirma um IP hospedado na China, `45.248.10.120`, como ponto central de comando e controle. Esse endereço é contatado pela amostra e por mais 7 arquivos maliciosos distintos no grafo, todos executáveis PE com detecção positiva. O histórico de resolução DNS desse IP soma 20 domínios, todos seguindo um padrão de nome curto e aleatório sob o TLD `.top`, como `kd3uw.top`, `g131.top` e `csvr.top`. Nenhum desses domínios individualmente carrega detecção positiva, mas o padrão de registro descartável em massa sob um TLD de baixo custo é uma assinatura comportamental típica de infraestrutura de C2 rotativa usada por loaders como Amadey, que trocam de domínio com frequência para dificultar bloqueio.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `5f160eb9a281a5f2a1a6ea1c5743d34fd3c0f1c34407ea1bd2d197e64cfa8c3c` |
| MD5 | `262373e7649042b5541bcab907599a71` |
| Nome do arquivo | `WF9(斩神专属).exe` |
| Tamanho | 38.610.702 bytes |
| Primeira submissão | 23/07/2026 09:47:01 UTC |
| Detecção | 7 vendors |
| Regras YARA associadas | 46 |

O tamanho de aproximadamente 38 MB é consistente com o padrão de inflação de arquivo já observado em outras amostras desta série (ScarfaceStealer e Vidar), possível técnica de evasão contra sandboxes com limite de upload.

---

## 3. Dropped Files (5)

| SHA256 | Tipo | Observações |
|---|---|---|
| `255a65d30841ab4082bd9d0eea79d49c5ee88f56136157d8d6156aef11c12309` | INI | Provável arquivo de configuração do loader, comportamento característico do Amadey. |
| `5b6de9816495a0367c8d5a5cf004a784f48965bee17e5dd11420ba7ac2f5720a` | PE DLL | Sem detecção individual. |
| `ae745de67efc0317cb45bb67b6f1cf95abfa3013bd6cb994cc23f809ba3ccb33` | COFF | Sem detecção individual. |
| `16eb11e65a2a4d2c9b08491f835f0408da3823808d5d476f176cb1c09bd1edd7` | Não informado | Sem atributos no export. |

---

## 4. Infraestrutura de Rede: IP de C2 na China

### 4.1 45.248.10.120

| Métrica | Valor |
|---|---|
| Arquivos maliciosos comunicando com o IP (incluindo a amostra atual) | 8 |
| Domínios no histórico de resolução | 20 |
| Domínios com detecção individual positiva | 0 |
| Registro de WHOIS histórico | 1 (sem detalhes adicionais no export) |

**Amostra do padrão de domínios (todos sob TLD .top)**

```
kd3uw.top
g131.top
207s.top
jqiq.top
cof0.top
mqj8.top
csvr.top
3x98.top
j52y.top
a40o.top
5ck0.top
8t4s.top
5dtj.top
z3f5.top
dw75.top
ur0s.top
ao9u.top
21hm.top
```

**Outros arquivos que comunicam com o mesmo IP**

| SHA256 |
|---|
| `4233848b237d635a183460869f55a11d04140a86979b11778c3292131dca7fea` |
| `93632b3b927bb20a6f11463fcfac854463cc1aaa4bc2c2d0d3fe134434a4f0e7` |
| `b0d00894a4b9d994a544d9b29099f2e16fc0eb0af245bed880dd90bc4fa957ab` |
| `c70a09eb910e88bcb57fa0a26acb564bb58d7cc21a73ce4d0a1234dbe0394902` |
| `d0594c82c4d9fb091d5625872911b7be6267813087267b644e9aa77b21cb7233` |
| `da37e812edea71f9afa2b4b9894d9a8c34154e1f322db25ca57e9fbb7af803ef` |
| `fd6afe54d18e79263917078705e78978ba75652dc8fb6bb79a6bb1ba3a83ab60` |

### 4.2 Outros indicadores contatados pela amostra

| Indicador | Detecção | Observações |
|---|---|---|
| `162.159.36.2` | Nenhuma | Faixa Cloudflare, ruído esperado. |
| URL única contatada | Nenhuma | Sem texto completo disponível no export atual. |

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Nome de arquivo temático de mod/cheat de jogo em chinês. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de C2 na China. |
| Dynamic Resolution | T1568 | Padrão de 20 domínios descartáveis sob TLD de baixo custo associados ao mesmo IP. |
| Ingress Tool Transfer | T1105 | Papel documentado do Amadey como loader de primeiro estágio para payloads adicionais. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 5f160eb9a281a5f2a1a6ea1c5743d34fd3c0f1c34407ea1bd2d197e64cfa8c3c

IP de C2: 45.248.10.120

Outros arquivos confirmados no mesmo C2:
4233848b237d635a183460869f55a11d04140a86979b11778c3292131dca7fea
93632b3b927bb20a6f11463fcfac854463cc1aaa4bc2c2d0d3fe134434a4f0e7
b0d00894a4b9d994a544d9b29099f2e16fc0eb0af245bed880dd90bc4fa957ab
```

---

## 7. Recomendações

1. Bloquear o IP `45.248.10.120` nos controles de perímetro.
2. Monitorar resolução de domínios curtos e aleatórios sob o TLD `.top` como padrão comportamental de hunting, já que o bloqueio individual de cada domínio tem baixo custo de substituição para o operador.
3. Verificar a presença do arquivo de configuração INI e da DLL dropados no ambiente monitorado, priorizando a checagem de payloads adicionais baixados pelo loader.
4. Orientar usuários sobre o risco de ferramentas de mod e cheat de jogos como vetor de entrada, dado o tema do nome de arquivo desta amostra.
5. Investigar os outros 7 arquivos que compartilham o mesmo IP de C2 para mapear se pertencem à mesma campanha de distribuição ou a clientes diferentes do mesmo serviço de loader.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura Amadey).
