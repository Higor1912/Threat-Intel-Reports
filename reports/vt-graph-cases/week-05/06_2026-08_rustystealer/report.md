# Threat Intelligence Report: RustyStealer

**ID:** week-05/06_2026-08_rustystealer
**Data:** 07/08/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como RustyStealer via assinatura no MalwareBazaar, com 7 detecções entre vendors e 34 regras YARA associadas. O nome do arquivo veio genérico (`file`), sem tema de isca identificável.

O IP contatado diretamente pela amostra, hospedado nos Estados Unidos, tem um histórico de resolução enxuto mas consistente: quatro domínios, dois deles subdomínios do mesmo domínio base `wspsurf.shop`, além de `status.xcapenet.ru` e `sengdostione.com`. Nenhum desses domínios apresenta detecção individual ainda, mas o padrão de dois subdomínios distintos sob a mesma raiz é consistente com uma estrutura de painel de C2 com múltiplos pontos de entrada. O mesmo IP também comunica com um segundo arquivo malicioso confirmado no grafo, reforçando que se trata de infraestrutura dedicada, não de um endereço compartilhado de uso genérico.

O restante do grafo exportado inclui um volume alto de coleções públicas e indicadores adicionais, mas sem ligação direta rastreável ao nó raiz desta amostra através das relações expandidas disponíveis. Optei por não apresentar esses dados como parte da investigação para evitar atribuir à amostra um contexto que não foi confirmado pela expansão do grafo.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | PE (executável Windows) |
| SHA256 | `254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b` |
| MD5 | `11b388e073236318b3851c168aa1abde` |
| Nome do arquivo | `file` (nome genérico) |
| Tamanho | 6.468.139 bytes |
| Primeira submissão | 07/08/2026 20:49:55 UTC |
| Última submissão | 07/08/2026 20:51:48 UTC |
| Detecção | 7 vendors |
| Regras YARA associadas | 34 |

---

## 3. Dropped Files (2)

Os 2 dropped files não trouxeram atributos detalhados no export atual. Recomenda se checagem manual direta no VT Graph para tipificação.

---

## 4. Infraestrutura de Rede

### 4.1 IP de Comando e Controle: 108.165.164.37 (Estados Unidos)

| Métrica | Valor |
|---|---|
| Arquivos comunicantes confirmados | 2, incluindo a amostra atual, ambos com detecção positiva |
| Domínios no histórico de resolução | 4 |
| Registro de WHOIS histórico | Presente |
| Certificado SSL histórico | Presente |

**Domínios do histórico de resolução**

| Domínio | Detecção |
|---|---|
| `luma.wspsurf.shop` | Nenhuma |
| `vexo.wspsurf.shop` | Nenhuma |
| `status.xcapenet.ru` | Nenhuma |
| `sengdostione.com` | Nenhuma |

Os dois subdomínios sob `wspsurf.shop` seguem convenção de nomenclatura de painel (nomes curtos tipo `luma` e `vexo`), sugestivo de múltiplos pontos de acesso para o mesmo backend de C2.

### 4.2 Segundo IP contatado

| IP | Detecção | Observações |
|---|---|---|
| `162.159.36.2` | Nenhuma | Faixa Cloudflare, ruído esperado. |

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de C2 dedicado. |
| Dynamic Resolution | T1568 | Múltiplos subdomínios de painel sob a mesma raiz associados ao mesmo IP. |
| Credentials from Password Stores | T1555 | Comportamento central e documentado da família RustyStealer. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): 254412f2ca69b69f8b686f874374e2584aaf55ad5c3e8ed6eddfa69f3fe6ea2b

IP de C2: 108.165.164.37

Domínios associados:
luma.wspsurf.shop
vexo.wspsurf.shop
status.xcapenet.ru
sengdostione.com
```

---

## 7. Recomendações

1. Bloquear o IP `108.165.164.37` e os domínios associados nos controles de perímetro, mesmo sem detecção individual confirmada em cada um.
2. Expandir manualmente os 2 dropped files sem atributos no export atual diretamente no VT Graph.
3. Investigar o segundo arquivo que comunica com o mesmo IP para mapear se pertence à mesma campanha.
4. Monitorar novos subdomínios sob `wspsurf.shop`, já que o padrão de nomenclatura sugere rotação de painel de C2.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura RustyStealer).
