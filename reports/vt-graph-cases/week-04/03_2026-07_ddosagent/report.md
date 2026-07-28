# Threat Intelligence Report: DDoSAgent

**ID:** week-04/03_2026-07_ddosagent
**Data:** 28/07/2026
**Analista:** Higor Silva
**Framework:** TLOA (Threat Led Offensive Audit)

---

## 1. Sumário Executivo

A amostra foi confirmada como DDoSAgent via assinatura no MalwareBazaar, com 4 detecções entre vendors e 21 regras YARA associadas. O nome do arquivo, `jbd2_sda1d`, imita a convenção de nomenclatura de threads do kernel Linux, especificamente o processo `jbd2/sda1-8`, responsável pelo journaling do sistema de arquivos ext4. Esse disfarce faz o processo malicioso passar despercebido em uma listagem rápida de processos do sistema, técnica de ofuscação comum em botnets de DDoS para dispositivos Linux e IoT.

O comportamento de rede confirma a natureza da família. A amostra contata `cloudflare.com` e `speed.cloudflare.com`, não como alvo de ataque, mas como ferramenta de benchmark: botnets de DDoS costumam usar o teste de velocidade da Cloudflare para medir a capacidade de upload do host infectado antes de recrutá-lo para um ataque, garantindo que o operador saiba a capacidade real de cada bot na rede.

O IP de comando e controle, hospedado nos Estados Unidos, comunica com 7 arquivos maliciosos adicionais, todos ELF ou shell scripts, consistente com uma botnet voltada a dispositivos Linux e IoT. Esse mesmo IP também é contatado diretamente por outros 3 arquivos distintos no grafo, além dos 7 já confirmados como comunicantes, reforçando o papel desse endereço como infraestrutura central da campanha.

---

## 2. Indicador Primário

| Campo | Valor |
|---|---|
| Tipo | ELF |
| SHA256 | `a963a61911c754a5f17f123bddfafd7a4d4ce2291051bc86e9fd60fe3af10d88` |
| MD5 | `0d714f361df6efb54cd722a926aa54b2` |
| Nome do arquivo | `jbd2_sda1d` |
| Tamanho | 4.784.276 bytes |
| Primeira submissão | 28/07/2026 07:40:33 UTC |
| Detecção | 4 vendors |
| Regras YARA associadas | 21 |

---

## 3. Dropped Files (3)

Os 3 dropped files não trouxeram atributos detalhados no export atual. Recomenda se checagem manual direta no VT Graph para tipificação.

---

## 4. Infraestrutura de Rede

### 4.1 Domínios contatados (2)

| Domínio | Detecção | Observações |
|---|---|---|
| `cloudflare.com` | Nenhuma | Provável uso para teste de velocidade/banda antes de recrutamento para ataque. |
| `speed.cloudflare.com` | Nenhuma | Serviço de benchmark de rede da Cloudflare, mesmo propósito do item acima. |

### 4.2 IP de Comando e Controle: 185.139.214.200 (Estados Unidos)

| Métrica | Valor |
|---|---|
| Arquivos comunicantes confirmados | 7 (6 ELF, 1 shell script), todos com detecção positiva |
| Outros arquivos que também contatam o IP diretamente | 3 |
| Certificados SSL históricos | 2 |
| Registro de WHOIS histórico | 1 |

### 4.3 Demais IPs contatados (4)

Faixas Cloudflare (IPv4 e IPv6), sem detecção, consistentes com o tráfego de benchmark descrito na seção 4.1.

### 4.4 URL Contatada

Uma URL sem detecção e sem texto completo disponível no export atual.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | ID | Justificativa |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | T1036.005 | Nome de processo imitando thread legítima do kernel Linux (`jbd2`). |
| Network Denial of Service | T1498 | Comportamento central e documentado da família DDoSAgent. |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação com o IP de comando e controle. |
| System Network Configuration Discovery | T1016 | Uso do teste de velocidade da Cloudflare para medir capacidade de upload antes do recrutamento para ataque. |

---

## 6. IoCs Consolidados

```
SHA256 (amostra principal): a963a61911c754a5f17f123bddfafd7a4d4ce2291051bc86e9fd60fe3af10d88

IP de comando e controle: 185.139.214.200
```

---

## 7. Recomendações

1. Bloquear o IP `185.139.214.200` nos controles de perímetro.
2. Monitorar processos com nomes que imitam threads do kernel Linux (`jbd2`, `kworker`, `kswapd`, entre outros) rodando fora do contexto esperado do kernel, técnica de disfarce recorrente em malware para Linux.
3. Tratar conexões a `speed.cloudflare.com` originadas de dispositivos IoT ou servidores sem função de diagnóstico de rede como comportamento suspeito, já que é um uso atípico para esse tipo de host.
4. Expandir manualmente os 3 dropped files sem atributos no export atual diretamente no VT Graph.
5. Consultar diretamente no VT Graph os certificados SSL e o registro de WHOIS histórico do IP de C2 para reconstruir a linha do tempo da infraestrutura.

---

## 8. Fontes

VirusTotal Graph (análise interativa e exportação JSON do grafo).
MalwareBazaar (confirmação da assinatura DDoSAgent).
