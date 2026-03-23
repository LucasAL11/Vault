# Baseline de Nonce (TTL + Single-use)

## Objetivo
Congelar o comportamento de seguranca de nonce para evitar regressao em:
- validade por TTL
- consumo de uso unico (single-use)

## Evidencia consolidada
- `tests/Infrastructure.Tests/NonceStoreTests.cs`
  - `NonceBaseline_TtlAndSingleUse_ShouldHoldAcrossReplayAndExpiry` (`Category=CriticalNonce`)
  - `TryConsumeAsync_ShouldConsumeOnce_AndRejectReplay`
  - `TryConsumeAsync_ShouldFailAfterExpiry`
  - `TryConsumeAsync_WithConcurrentReplay_ShouldAllowOnlySingleConsume`
- `tests/Api.IntegrationTests/NonceChallengeIntegrationTests.cs`
  - `VerifyChallenge_ShouldConsumeNonce_AndRejectReplay`
  - `RespondChallenge_ShouldRejectReplayAfterFirstUse`
  - `RespondChallenge_WithClockSkewOutsideWindow_ShouldReturnUnauthorized`

## Gate obrigatorio no CI
- Workflow: `.github/workflows/nonce-regression.yml`
- Filtro obrigatorio: `Category=CriticalNonce`
- Regra de falha:
  - zero testes executados => falha
  - qualquer teste nao aprovado => falha

## Execucao local
```powershell
dotnet test tests/Infrastructure.Tests/Infrastructure.Tests.csproj --filter "Category=CriticalNonce"
```
