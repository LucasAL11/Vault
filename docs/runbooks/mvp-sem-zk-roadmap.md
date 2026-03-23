# Roadmap Tecnico: MVP sem ZK

## Status da revisao
- Revisado em: 2026-03-23
- Escopo oficial: MVP sem dependencia de ZK.
- Decisao: componentes ZK atuais ficam classificados como legado, fora do objetivo do MVP.

## Objetivo do MVP
Entregar fluxo de cofre de segredos com controle de acesso, anti-replay, auditoria e operacao segura, sem depender de prover/verifier zero-knowledge.

## Escopo do MVP (in scope)
- Autenticacao e autorizacao por AD/JWT.
- Vault por grupo AD com politicas de acesso.
- Escrita e leitura de metadados de segredo.
- Request de valor com contrato versionado `v1`:
  - `contractVersion`, `reason`, `ticket`, `clientId`, `nonce`, `issuedAt`, `proof`.
- Challenge + nonce com TTL, single-use e audience.
- Validacao de proof HMAC em tempo constante.
- Rate limiting nas rotas sensiveis.
- Auditoria de operacoes de segredo e de negacao.
- Documentacao operacional e testes minimos obrigatorios.

## Fora do escopo do MVP (out of scope)
- Reintroducao de rotas `/Cryptography/*` no runtime MVP.
- Dependencia de backend externo ZK (gnark/circom/halo2).
- Hardening criptografico para algebra/circuitos ZK in-process.
- Meta de prova zero-knowledge formal no fluxo do cofre.

## Legado classificado (nao objetivo do MVP)
- Rotas ZK foram removidas do runtime da API e nao fazem parte do fluxo MVP.
- Namespace e codigo `Infrastructure/Zk/*` permanecem como legado tecnico.
- Runbooks ZK permanecem para referencia historica:
  - `docs/runbooks/zk-in-process-limits.md`
  - `docs/runbooks/zk-bls12-calculo-completo.md`

## Arquitetura alvo do MVP sem ZK
1. Cliente autenticado solicita nonce: `POST /auth/challenge`.
2. Cliente monta prova HMAC com contrato `v1`.
3. Cliente solicita segredo: `POST /vaults/{vaultId}/secrets/{name}/request`.
4. API valida autorizacao, nonce, proof e janela temporal.
5. API registra auditoria e retorna resposta conforme politica do produto.

## Trilha de execucao (fases)

### Fase 1 - Contrato e seguranca de entrada
- Contrato `v1` obrigatorio e validado.
- Compatibilidade legada controlada (`ticketId`/`issuedAtUtc`) apenas como alias temporario.
- Respostas de erro padronizadas para contrato invalido.
- Rotas ZK removidas do runtime da API no caminho MVP.

### Fase 2 - Operacao e observabilidade
- Rate limit por rota sensivel.
- Metricas de nonce emitido/consumido/rejeitado/expirado.
- Alertas de pico de 401/403/429.

### Fase 3 - Escala e resiliencia
- Nonce store distribuido (Redis/DB) para multi-instancia.
- Testes de concorrencia e replay cross-node.
- Plano de rollout com feature flag e rollback.

## Gate de producao do MVP (go/no-go)
- Fluxo request/challenge/proof validado ponta a ponta.
- Anti-replay validado com testes automatizados.
- Auditoria sem vazamento de segredo/proof/chave.
- Rate limit ativo e monitorado.
- Sign-off conjunto: Produto + Seguranca + Plataforma.

## Criterios de manutencao do escopo
- Todo ticket novo deve declarar explicitamente: `MVP sem ZK`.
- Qualquer item com dependencia ZK deve ser classificado como backlog pos-MVP.
- Alteracoes em legado ZK so podem ser:
  - correcao critica de seguranca;
  - ajuste de compatibilidade estritamente necessario.
