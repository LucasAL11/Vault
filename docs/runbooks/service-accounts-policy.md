# Politica: Service Accounts (Clientes Maquina)

## Objetivo
Padronizar identificacao, escopo minimo e rotacao de credenciais para clientes maquina que usam `AuthChallenge:ClientSecrets`.

## Escopo
Aplica para:
- qualquer `clientId` usado por integracoes nao-humanas
- fluxos com `POST /auth/challenge`, `POST /auth/challenge/respond` e `POST /vaults/{vaultId}/secrets/{name}/request`

Nao aplica para:
- usuario humano com login interativo
- contas de operador para endpoints `/ops/*`

## 1) Padrao de identificacao

Formato obrigatorio do `clientId`:
`sa-<sistema>-<funcao>-<ambiente>-v<nn>`

Regex de referencia:
`^sa-[a-z0-9]+-[a-z0-9-]+-(dev|hml|stg|prd)-v[0-9]{2}$`

Regras:
- usar apenas minusculas, numeros e `-`
- versionar no proprio `clientId` (`v01`, `v02`, ...)
- um `clientId` por workload e por ambiente
- proibido usar nome de pessoa, time temporario ou finalidade generica (`sa-temp`, `sa-test`)

Exemplos validos:
- `sa-payments-vault-reader-prd-v01`
- `sa-crm-secret-request-dev-v03`

Exemplos invalidos:
- `local-dev-client`
- `SA-PAYMENTS-PRD`
- `sa-ops-admin-prd-v01` (escopo indevido para cliente maquina)

## 2) Escopo minimo obrigatorio

Principio: menor privilegio por default.

Regras:
- cada `clientId` deve ter uma unica finalidade de negocio
- audience permitida deve ser explicitamente definida no onboarding
- default recomendado para leitura controlada de segredo: `vault.secret.request`
- nao usar service account em endpoints operacionais (`/ops/killswitch`, `/ops/key-provider/*`)
- separar credenciais por ambiente (`dev/hml/stg/prd`), sem compartilhamento cruzado
- toda conta deve ter owner tecnico e owner de negocio definidos em ticket

Campos minimos de cadastro (obrigatorios):
- `clientId`
- sistema
- owner tecnico
- owner negocio
- ambiente
- audience(s) autorizada(s)
- justificativa de acesso
- data de expiracao/revisao

## 3) Rotacao de credenciais

### 3.1 Rotacao periodica
- periodicidade padrao: a cada 90 dias
- sistemas criticos: a cada 30 dias

### 3.2 Rotacao emergencial
Acionar imediatamente em:
- suspeita de vazamento de `clientSecret`
- evidencias de uso indevido do `clientId`
- incidente de chave comprometida com impacto em autenticacao de cliente maquina

### 3.3 Procedimento padrao (modelo sem downtime)
1. Criar novo `clientId` versionado (`vNN+1`) e novo segredo forte.
2. Adicionar em `AuthChallenge:ClientSecrets` sem remover o anterior.
3. Publicar configuracao e reiniciar/deploy controlado.
4. Atualizar cliente consumidor para novo `clientId`/segredo.
5. Validar sucesso do fluxo com nonce/proof.
6. Remover `clientId` antigo do `AuthChallenge:ClientSecrets`.
7. Registrar evidencia no ticket de mudanca.

Observacao:
- na implementacao atual, cada `clientId` tem um unico segredo ativo; por isso a rotacao segura e feita por versao de `clientId`.

## 4) Revogacao e contencao

Quando comprometida:
1. remover imediatamente o `clientId` comprometido de `AuthChallenge:ClientSecrets`
2. avaliar ativacao de kill switch conforme severidade
3. abrir incidente e seguir `docs/runbooks/chave-comprometida.md`
4. executar rotacao emergencial e validar logs/auditoria

## 5) Auditoria e rastreabilidade

Obrigatorio manter:
- ticket de criacao (onboarding)
- ticket de rotacao (periodica ou emergencial)
- evidencias de validacao tecnica
- owner responsavel e data UTC

Retencao recomendada:
- minimo 12 meses para trilhas de aprovacao e evidencias

## 6) Checklist operacional (template)

Marcar `SIM` ou `NAO`.

- [ ] `clientId` segue formato `sa-<sistema>-<funcao>-<ambiente>-v<nn>`
- [ ] workload possui dono tecnico e dono de negocio
- [ ] audience autorizada foi definida e aprovada
- [ ] escopo minimo validado (sem acesso a `/ops/*`)
- [ ] segredo forte gerado e armazenado em cofre seguro
- [ ] rotacao planejada com data limite documentada
- [ ] teste de autenticacao (challenge/respond/request) executado
- [ ] `clientId` anterior removido (quando aplicavel)
- [ ] evidencias anexadas em ticket
- [ ] Security e SRE deram sign-off

Criterio de aceite:
- checklist aprovado apenas com 100% dos itens obrigatorios em `SIM`

## 7) AC - Checklist operacional aprovado (exemplo de evidencia)

Referencia de aceite para este requisito:

- [x] politica documentada com padrao de identificacao
- [x] politica documentada com escopo minimo
- [x] politica documentada com rotacao periodica e emergencial
- [x] checklist operacional publicado no runbook
- [x] criterio objetivo de aprovacao definido

Resultado AC:
- `APROVADO`
