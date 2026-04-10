# Politica: Retencao e Expiracao de Versoes de Segredo

## Objetivo
Definir e padronizar regras de retencao de versoes e expiracao (`expiresUtc`) por tipo de segredo e ambiente do vault.

## Escopo
Aplica para gravacao de segredo em:
- `PUT /vaults/{vaultId}/secrets/{name}`

Base tecnica:
- classificacao por tipo de segredo (derivada do nome e `contentType`)
- ambiente do vault (`Production`, `Staging`, `Development`)
- regras de `SecretVersionRetention` em `appsettings*.json`

## Classificacao de tipo de segredo

Categorias usadas pela politica:
- `Credential`
- `Token`
- `Certificate`
- `Generic`

Heuristica resumida:
- `Certificate`: nomes com `CERT`, `CERTIFICATE`, `PEM`, `PFX` ou `contentType` relacionado
- `Token`: nomes com `TOKEN`, `JWT`, `BEARER`, `SESSION`
- `Credential`: nomes com `PASSWORD`, `PASS`, `PWD`, `SECRET`, `API_KEY`, `CONNECTION`, `KEY`
- `Generic`: qualquer outro caso

## Regras oficiais (matriz)

### Production
- `Credential`: reter `20` versoes, expiracao padrao `30` dias, maximo `90` dias
- `Token`: reter `10` versoes, expiracao padrao `7` dias, maximo `14` dias
- `Certificate`: reter `8` versoes, expiracao padrao `365` dias, maximo `825` dias
- `Generic`: reter `30` versoes, expiracao padrao `90` dias, maximo `365` dias

### Staging
- `Credential`: reter `10` versoes, expiracao padrao `14` dias, maximo `30` dias
- `Token`: reter `8` versoes, expiracao padrao `3` dias, maximo `14` dias
- `Certificate`: reter `6` versoes, expiracao padrao `90` dias, maximo `365` dias
- `Generic`: reter `15` versoes, expiracao padrao `30` dias, maximo `180` dias

### Development
- `Credential`: reter `5` versoes, expiracao padrao `3` dias, maximo `14` dias
- `Token`: reter `5` versoes, expiracao padrao `1` dia, maximo `7` dias
- `Certificate`: reter `5` versoes, expiracao padrao `30` dias, maximo `90` dias
- `Generic`: reter `10` versoes, expiracao padrao `7` dias, maximo `30` dias

### Fallback
- `*/*`: reter `20` versoes, expiracao padrao `30` dias, maximo `180` dias

## Comportamento aplicado pela API

1. Se `expiresUtc` nao for enviado:
- a API aplica expiracao padrao da regra (`DefaultExpirationDays`).

2. Se `expiresUtc` for enviado:
- deve estar no futuro;
- deve respeitar janela minima (`MinExpirationMinutes`);
- deve respeitar janela maxima (`MaxExpirationDays`);
- fora da regra: `400 BadRequest`.

3. Apos gravar nova versao:
- versoes mais antigas alem do limite `MaxVersionsToRetain` sao removidas.
- a poda e puramente por ordem de versao (nao diferencia revogada vs. ativa).

4. Auditoria:
- escrita inclui metadados da regra aplicada (`retentionRule`, `secretType`, `maxVersions`, `pruned`).

## Excecoes e mudancas
- qualquer alteracao da matriz deve ter aprovacao de Security + Plataforma
- mudanca de limite em `Production` exige ticket com analise de impacto
- alteracoes devem atualizar este runbook e `appsettings*.json` no mesmo PR

## Checklist operacional de conformidade
- [ ] tipo de segredo validado na convencao de nomenclatura
- [ ] ambiente do vault confirmado (`Production/Staging/Development`)
- [ ] regra de expiracao aplicada/validada no endpoint de escrita
- [ ] retencao de versoes validada (prune esperado)
- [ ] auditoria contem metadados da politica
- [ ] alteracao aprovada por Security e Plataforma

Criterio de aceite:
- checklist aprovado apenas com todos os itens em conformidade.

## Evidencia de validacao (AC)
- politica publicada neste runbook
- politica aplicada em runtime via `SecretVersionRetention`
- cobertura automatizada em `tests/Api.IntegrationTests/SecretStoreIntegrationTests.cs` para:
  - expiracao padrao por tipo/ambiente
  - rejeicao de expiracao fora da janela
  - prune por limite de versoes
