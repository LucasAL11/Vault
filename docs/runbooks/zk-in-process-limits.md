# Runbook: Limites do ZK In-Process

> STATUS: LEGADO (fora do escopo do MVP sem ZK desde 2026-03-23).
> Uso permitido apenas para compatibilidade controlada.
> Rotas ZK foram removidas do runtime da API no caminho MVP.

## Objetivo
Documentar limites técnicos e operacionais do backend `InProcessZkBackend` para evitar uso incorreto em produção.

## Escopo
- Endpoint de prova/verificação (`/Cryptography/zk` e `/Cryptography/verify`)
- Backend `Infrastructure/Zk/Backends/InProcessZkBackend.cs`
- Witness local (`IZkWitnessGenerator`)

## O que o modo in-process faz
- Gera payload de prova assinado por HMAC local (`ZkBackend:LocalHmacKey`).
- Não inclui segredo em claro no payload de prova.
- Versiona esquema do payload via `SchemaVersion`.
- Valida `clientId`, `nonce`, `hashPublic`, `circuitId`, `version` e assinatura MAC no verify.

## Limites de segurança
- Não é um prover ZK real (não há construção/validação SNARK).
- Não oferece zero-knowledge criptográfico formal.
- Modelo de confiança é servidor-cêntrico: quem controla a API e a chave HMAC controla provas válidas.
- Não há verificabilidade pública/offline por terceiros.

## Limites de arquitetura
- Solução acoplada ao processo da API (sem separação prover/verifier).
- Escalabilidade horizontal depende de segredo HMAC consistente entre instâncias.
- Rotação de `LocalHmacKey` invalida provas antigas assinadas com chave anterior (sem key ring de verificação para proof legado).
- Não substitui circuito/proving key/verifying key de stacks como Circom/gnark/halo2.

## Limites de interoperabilidade
- Proof payload é contrato interno da aplicação.
- Alterações de `SchemaVersion` exigem compatibilidade explícita no `verify`.
- Consumers externos não devem depender de formato interno sem contrato versionado público.

## Requisitos operacionais mínimos
- Em `Production`, `LocalHmacKey` forte é obrigatório:
  - rejeita chave default;
  - aceita Base64 com >= 32 bytes ou segredo forte equivalente.
- `nonce` deve ser emitido e consumido corretamente no fluxo challenge/verify para reduzir replay.
- Logs não devem incluir segredo, payload sensível ou chave.

## Quando usar
- Ambientes de desenvolvimento/homologação.
- Fallback temporário enquanto prover real não está integrado.
- Cenários internos com risco aceito e sem exigência de prova ZK formal.

## Quando não usar
- Requisitos regulatórios/criptográficos de prova zero-knowledge formal.
- Necessidade de verificabilidade independente por terceiros.
- Cenários multi-tenant críticos com fronteira forte de confiança entre partes.

## Plano de evolução recomendado
1. Introduzir backend de prover real (ex.: gnark/circom) atrás de `IZkBackend`.
2. Publicar contrato de prova versionado externamente (com política de compatibilidade).
3. Suportar key ring de verificação para transição de chaves sem quebra abrupta.
4. Adicionar suíte de testes de compatibilidade entre versões de schema.
