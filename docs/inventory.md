# Inventário funcional das 33 fichas — passo zero (D-097)

> **Método:** para cada ficha, extraí os símbolos `pub` REAIS do ficheiro Zig fonte
> (não do texto da ficha) e verifiquei a presença de cada um no Rust por nome
> (`sym` ou `snake_case(sym)` como fn/struct/enum/const/type). BE-\* "com teste" =
> id citado literalmente em `tests/*.rs` (ambos os formatos; semânticas cobertas
> sem citação não contam — conservador por desenho). Veredictos curados à mão por
> quem escreveu os dois lados; onde a curadoria marca "auditar W10", a contagem
> mecânica não distingue densidade de funcionalidade e só a auditoria item a item
> da ficha decide.
>
> **Critério de paridade ratificado (Daniel, D-097):** cada item de cada ficha
> implementado + teste nomeado. Ficheiros mentem; fichas não.

## Tabela (33 fichas)

| ficha | zig | rs | %sig | BE-t | veredicto curado | wave |
|---|---|---|---|---|---|---|
| intent | 216 | 154 | 100% | 3/4 | **FUNCIONAL** (nomes 1:1) | feita |
| reassembly | 240 | 204 | 100% | 0/0 | **FUNCIONAL** | feita |
| session | 215 | 225 | 100% | 0/0 | **FUNCIONAL** (replay-window incluído aqui) | feita |
| main | 269 | 89 | 100% | 0/0 | **FUNCIONAL** (boot simplificado; re-ver no wiring W9) | feita |
| noise | 460 | 443 | 95% | 0/0 | **FUNCIONAL** (2 tipos → dalek; densidade, não falha) | feita |
| grant_ledger | 554 | 355 | 90% | 2/3 | **FUNCIONAL** (2 tipos com outra forma; FirstReceipt/Orphan vivem) | feita |
| sync | 289 | 146 | 72% | 0/1 | **PARCIAL** — SyncEngine/WalkQueue como API em falta | W10 |
| ca_material | 297 | 219 | 72% | 1/2 | **FUNCIONAL** (3 helpers inline; densidade) | feita |
| relay | 255 | 165 | 70% | 1/1 | **PARCIAL** — drain/parse-registration em falta | W10 |
| handshake | 75 | 722 | 60% | 0/1 | **PARCIAL** — processDatagram vive no daemon.rs com outra forma; auditar | W10 |
| control | 444 | 208 | 60% | 0/0 | **PARCIAL** — servidor HTTP presente; API de erros/constantes diferente | W10 |
| mac | 173 | 47 | 50% | 0/0 | **PARCIAL REAL** — mecanismo de cookies (issueCookie/rotate) NÃO portado | W10 |
| replay | 114 | 0 | 50% | 0/0 | **DENSIDADE** — sliding window já vive em session.rs | feita |
| http_parse | 139 | 208 | 33% | 0/0 | **DENSIDADE** — parser inline no control.rs; API Request/Method diferente; auditar | W10 |
| parser | 328 | 558 | 34% | 0/1 | **DENSIDADE** — transport headers vivem em noise.rs com outros nomes; auditar item a item | W10 |
| daemon | 342 | 279 | 33% | 0/0 | **PARCIAL REAL** — wiring resolveAndAdmit/dispatch/F1 em falta | W9 |
| keys | 194 | 498 | 30% | 0/1 | **PARCIAL** — funcionalidade espalhada por daemon/ca; API Keys não existe como módulo | W10 |
| listener | 173 | 0 | 35%* | 0/0 | **AUSENTE** (*falsos positivos: símbolos genéricos) | W9 |
| relay_serve | 216 | 165 | 15% | 0/1 | **PARCIAL REAL** — role-gate served-cert/drain em falta | W9 |
| relay_store | 143 | 0 | 15%* | 1/1 | **AUSENTE** — store-and-forward não portado | W9 |
| ledger (envelope) | 333 | 0 | 20%* | 0/7 | **AUSENTE** — envelope store não portado (*falsos positivos) | W9 |
| token | 78 | 0 | 25% | 0/0 | **AUSENTE** | W9 |
| render | 56 | 0 | 25% | 1/3 | **AUSENTE** | W9 |
| binding | 190 | 0 | 29%* | 1/2 | **AUSENTE** — binding frames não portado (*falsos positivos) | W9 |
| resolver | 322 | 0 | 13% | 1/1 | **AUSENTE** | W7 |
| dispatch | 352 | 0 | 28%* | 2/3 | **AUSENTE** (*falsos positivos de símbolos genéricos) | W7 |
| verify | 711 | 0 | 22% | 1/4 | **AUSENTE** — só verify_signed existe; ladder 0-11/refusals/control/mesh/admission zero | W7 |
| grant_trace | 163 | 0 | 0% | 1/1 | **AUSENTE** (instrumento TLA) | W8 |
| historical | 105 | 0 | 0% | 0/4 | **AUSENTE** — inclui a prova por tipos do no-clock | W8 |
| evidence | 294 | 0 | 6% | 0/3 | **AUSENTE** | W8 |
| dag | 190 | 0 | 25%* | 0/3 | **AUSENTE** (*falsos positivos) | W8 |
| control_api | 339 | 208 | 5% | 0/0 | **PARCIAL REAL** — /v1/intents, /v1/intents/{id}, /v1/events NÃO existem | W10 |
| ca_cli | 187 | 89 | 0%* | 0/2 | **DENSIDADE** — funcionalidade em main.rs com outra forma (*sym zig não transferidos) | feita |

## Resposta à pergunta do owner: densidade vs funcionalidade

| Camada | Linhas Zig | Estado |
|---|---|---|
| **Funcional (portada)** | ~2.950 (10 fichas) | testada: 174 testes, mutação 21/21, cross-diff 6/6, 2 soaks |
| **Densidade/shape (funcionalidade presente, API diferente)** | ~1.400 (8 fichas) | auditar item a item na W10 antes de declarar |
| **Parcial real (gaps dentro de portados)** | dentro das acima | control_api 5%, mac cookies, relay drain, daemon wiring, keys API, sync engine |
| **Ausente (zero código)** | ~3.050 (13 fichas) | verify 711 · dispatch 352 · resolver 322 · ledger-env 333 · evidence 294 · binding 190 · dag 190 · listener 173 · grant_trace 163 · relay_store 143 · historical 105 · token 78 · render 56 |

**Números citáveis:** assinaturas 243/506 (48%) · linhas 4.982/8.456 (59%, mas linhas mentem — daí este inventário) · BE citados em testes 15/49 (o resto está coberto por semântica sem citação ou não está coberto — a W7-W10 fecha isto ficha a ficha).

## Âmbito por onda (sai da tabela, não de palpite)

- **W7 autoridade**: verify + dispatch + resolver = **1.385 linhas Zig**, a mais densa (F1/F13/F15/F16, ladder BE-GRANT 0-11)
- **W8 audit/attestation**: evidence + dag + historical + grant_trace = **752 linhas**, inclui prova por tipos do no-clock
- **W9 suporte + wiring**: listener + binding + token + relay_store + render + ledger-envelope + wiring do daemon (resolveAndAdmit/dispatch/F1) = **~1.475 linhas**
- **W10 completar portado**: control_api + mac cookies + relay drain + keys API + sync engine + auditorias parser/http_parse/handshake = âmbito exacto sai da auditoria item a item
