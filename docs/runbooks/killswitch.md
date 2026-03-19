# Runbook: Kill Switch E2E

## Objetivo
Ativar e desativar o kill switch da API com segurança durante incidentes, reduzindo impacto e mantendo acesso operacional para administradores autorizados.

## Escopo
Este runbook cobre:
- Ativação do kill switch em runtime
- Validação técnica de bloqueio
- Desativação e retorno ao estado normal
- Operação de denylist temporária por usuário
- Troubleshooting de erros `401`/`403`

## Pré-requisitos
- API em execução
- Usuário autenticado e autorizado no grupo AD configurado em `KillSwitch:AllowedGroup`
- JWT válido
- Base URL conhecida (ex.: `http://localhost:5065`)

## Endpoints usados
- `GET /ops/killswitch`
- `POST /ops/killswitch`
- `GET /ops/killswitch/debug`
- `GET /debug/time`
- `GET /ops/killswitch/denylist`
- `POST /ops/killswitch/denylist`
- `DELETE /ops/killswitch/denylist/{username}`

## Variáveis de execução (exemplo)
```text
BASE_URL=http://localhost:5065
TOKEN=<jwt>
```

## Procedimento de Ativação
1. Verifique o estado atual:
```http
GET {{BASE_URL}}/ops/killswitch
Authorization: Bearer {{TOKEN}}
```

2. Ative o kill switch:
```http
POST {{BASE_URL}}/ops/killswitch
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{
  "enabled": true,
  "allowedGroup": "Admins",
  "retryAfterSeconds": 120,
  "message": "Service temporarily unavailable."
}
```

3. Valide resposta esperada:
- `200 OK`
- `enabled = true`

## Validação E2E Pós-Ativação
1. Endpoint funcional comum deve bloquear:
```http
GET {{BASE_URL}}/debug/time
```
Esperado: `503 Service Unavailable`.

2. Endpoint operacional deve continuar acessível para admin:
```http
GET {{BASE_URL}}/ops/killswitch
Authorization: Bearer {{TOKEN}}
```
Esperado: `200 OK`.

## Procedimento de Desativação
1. Desative o kill switch:
```http
POST {{BASE_URL}}/ops/killswitch
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{
  "enabled": false
}
```

2. Valide normalização:
- `GET /ops/killswitch` retorna `enabled = false`
- `GET /debug/time` volta para `200 OK`

## Denylist Temporária
Use denylist para bloquear um usuário específico por tempo limitado, mesmo com kill switch desligado.

1. Adicionar usuário por 30 minutos:
```http
POST {{BASE_URL}}/ops/killswitch/denylist
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{
  "username": "lucas.luna",
  "durationMinutes": 30,
  "reason": "Investigacao de incidente"
}
```

2. Listar denylist ativa:
```http
GET {{BASE_URL}}/ops/killswitch/denylist
Authorization: Bearer {{TOKEN}}
```

3. Remover usuário manualmente:
```http
DELETE {{BASE_URL}}/ops/killswitch/denylist/lucas.luna
Authorization: Bearer {{TOKEN}}
```

Resposta esperada quando usuário está negado:
- `403 Forbidden`
- mensagem indicando bloqueio temporário e data de expiração.

## Troubleshooting
### `401 Unauthorized`
- Token ausente/expirado/inválido.
- Verifique `iss`, `aud`, validade (`nbf`/`exp`) e assinatura.

### `403 Forbidden`
- Usuário não autorizado no grupo AD esperado.
- Verifique `KillSwitch:AllowedGroup` com o `sAMAccountName` correto.
- Use diagnóstico:
```http
GET {{BASE_URL}}/ops/killswitch/debug
Authorization: Bearer {{TOKEN}}
```
Valide campos:
- `Username`
- `requiredGroup`
- `canOperate`

### Prompt de credencial Windows no navegador
- Esperado no modo híbrido (`BearerOrNegotiate`) quando a chamada não envia bearer token.
- Para forçar JWT, sempre envie `Authorization: Bearer <token>`.

## Checklist Operacional
- Incidente confirmado e comunicado
- Kill switch ativado
- Bloqueio validado (`503` em endpoint comum)
- Acesso operacional preservado para admin
- Monitoramento acompanhado durante mitigação
- Kill switch desativado após estabilização
- Validação final (`200` em endpoint comum)
- Pós-mortem registrado

## Observações
- O kill switch é runtime e não exige restart da API.
- Mudança de `AllowedGroup` deve ser controlada e auditada.
