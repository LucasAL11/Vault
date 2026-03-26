# Runbook: Resposta a Chave Comprometida

## Objetivo
Conter impacto de suspeita/confirmacao de chave comprometida, executar rotacao emergencial, re-encrypt controlado e comunicacao de incidente com trilha auditavel.

## Escopo
Este runbook cobre:
- Chave ativa do `KeyProvider` (`/ops/key-provider`, `/ops/key-provider/rotate`, `/ops/key-provider/re-encrypt`)
- Contencao operacional via kill switch (`/ops/killswitch`)
- Comunicacao de incidente (interna e externa)

Nao cobre:
- Forense detalhada do host/infra (deve seguir playbook de seguranca corporativo)
- Vazamento de segredo individual sem comprometimento de chave mestra

## Quando acionar
Acione imediatamente em qualquer uma das condicoes:
- Exposicao de `APP_KEY_BASE64`, chave do key ring `Prod:Keys`, ou credencial de KMS
- Evidencia de uso nao autorizado de `POST /ops/key-provider/rotate` ou `POST /ops/key-provider/re-encrypt`
- Evidencia de decrypt indevido em massa de segredos

Classificacao inicial:
- `SEV-1`: exfiltracao confirmada ou uso ativo malicioso
- `SEV-2`: suspeita forte sem confirmacao de uso

## Papeis minimos
- `IC` (Incident Commander): coordena decisoes e aprovacoes
- `SRE/Plataforma`: executa contencao e rotacao
- `Security`: classifica impacto e define obrigacoes regulatorias
- `App Owner`: valida servico e integridade funcional apos mitigacao

## Pre-requisitos
- Token valido com permissao no grupo `KeyProvider:OperatorsGroup`
- Acesso ao canal oficial de incidente (war room)
- Base URL da API e inventario de vaults/segredos

## Fase 0 - Contencao (T+0 ate T+15 min)
1. Abrir incidente e congelar mudancas nao relacionadas.
2. Se houver risco de uso ativo, ativar kill switch:
```http
POST /ops/killswitch
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": true,
  "retryAfterSeconds": 120,
  "message": "Service temporarily unavailable due to security incident."
}
```
3. Confirmar estado operacional:
```http
GET /ops/killswitch
Authorization: Bearer <token>
```
4. Coletar evidencias imediatas:
   - Logs estruturados do periodo (requests de `/ops/key-provider/*`, falhas 401/403/429)
   - Snapshot do estado da chave ativa:
```http
GET /ops/key-provider
Authorization: Bearer <token>
```
5. Registrar timestamps (UTC) de cada acao.

## Fase 1 - Rotacao emergencial (T+15 ate T+60 min)
1. Gerar nova chave forte (>=32 bytes) e novo `keyId`.
2. Inserir no key ring de producao sem remover a chave antiga.
3. Rotacionar chave ativa em runtime:
```http
POST /ops/key-provider/rotate
Authorization: Bearer <token>
Content-Type: application/json

{
  "keyId": "prod-key-vNEXT"
}
```
4. Validar retorno:
   - `200 OK`
   - `CurrentKeyId = prod-key-vNEXT`
5. Revalidar estado:
```http
GET /ops/key-provider
Authorization: Bearer <token>
```
6. Se a rotacao falhar, manter kill switch ativo e escalar para Security/Plataforma.

## Fase 2 - Re-encrypt emergencial (T+1h ate T+4h)
Re-encrypt e por segredo (vault + secretName). Execute em lotes controlados.

### 2.1 Fluxo por segredo
```http
POST /ops/key-provider/re-encrypt
Authorization: Bearer <token>
Content-Type: application/json

{
  "vaultId": "<guid-vault>",
  "secretName": "DB_PASSWORD",
  "includeRevoked": false,
  "includeExpired": false
}
```

Resposta esperada:
- `200 OK`
- `TargetCount` e `RotatedCount`
- `CurrentKeyId` igual a chave nova

Comportamentos importantes:
- `409 Conflict`: retry e seguro (concorrencia)
- `404 NotFound`: segredo inexistente ou sem versoes
- Operacao e idempotente quando `RotatedCount = 0`

### 2.2 Ordem recomendada
1. Segredos de autenticacao externa e banco
2. Segredos de integracao critica
3. Demais segredos

### 2.3 Criterio de conclusao tecnica
- 100% dos segredos de escopo executados com sucesso
- `RotatedCount > 0` onde havia versao em chave antiga
- Nenhum erro pendente de reprocessamento

## Fase 3 - Validacao pos-rotacao
1. Validar leitura autorizada de segredos criticos (smoke funcional).
2. Validar trilha de auditoria:
   - `KEY_ROTATE`
   - `SECRET_REENCRYPT`
3. Manter monitoramento reforcado por no minimo 24h:
   - picos de `401`, `403`, `429`, `5xx`
   - tentativas em `/ops/key-provider/*`

## Fase 4 - Retorno controlado
Quando estabilizado:
1. Desativar kill switch (se ativado).
2. Comunicar normalizacao para stakeholders.
3. Abrir itens obrigatorios de follow-up:
   - Rotacao de credenciais correlatas (`AuthChallenge:ClientSecrets`, `Jwt:Secret`, credenciais KMS)
   - Endurecimento de acesso operacional
   - Revisao de lacunas de deteccao

## Comunicacao de incidente
Use mensagens curtas, factuais e com horario UTC.

### Template 1 - Aviso inicial (interno)
```
[SEV-X][UTC <timestamp>] Suspeita de chave comprometida no KeyProvider.
Contencao iniciada. Kill switch: <on/off>.
Impacto atual: <descricao objetiva>.
Proxima atualizacao em <N> minutos.
```

### Template 2 - Atualizacao de mitigacao
```
[SEV-X][UTC <timestamp>] Rotacao emergencial concluida.
CurrentKeyId: <novo-key-id>.
Re-encrypt: <N>/<Total> segredos concluido.
Risco residual: <baixo/medio/alto>.
```

### Template 3 - Encerramento tecnico
```
[SEV-X][UTC <timestamp>] Mitigacao concluida.
Kill switch: <estado>.
Rotacao: concluida em <timestamp>.
Re-encrypt: 100% do escopo.
Proximos passos: post-mortem e acoes corretivas ate <data>.
```

### Checklist de conteudo minimo para Security/Compliance
- Linha do tempo (UTC)
- Escopo de chaves e segredos afetados
- Evidencias de acesso indevido (se houver)
- Medidas de contencao e recuperacao
- Risco residual e plano de acompanhamento

## Checklist rapido de execucao
- Incidente aberto e classificado (`SEV-1` ou `SEV-2`)
- Kill switch avaliado/acionado
- `CurrentKeyId` rotacionado com sucesso
- Re-encrypt executado em todo o escopo
- Auditoria e monitoramento confirmados
- Comunicacoes enviadas nos marcos (inicio, progresso, encerramento)
- Follow-up registrado (post-mortem + hardening)
