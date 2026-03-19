# Runbook: KeyProvider em `ProdKms`

## Objetivo
Remover chave estática em Base64 da aplicação e delegar gestão de chave para KMS/HSM (via gateway HTTP interno).

## Configuração
```json
"KeyProvider": {
  "Mode": "ProdKms",
  "OperatorsGroup": "Administradores de Chaves",
  "ProdKms": {
    "Enabled": true,
    "BaseUrl": "https://kms.internal.local",
    "KeysEndpointPath": "/v1/keyring",
    "RotateEndpointPath": "/v1/keyring/rotate",
    "ApiKey": "<secret-store-ref>",
    "ApiKeyHeaderName": "X-API-Key",
    "TimeoutSeconds": 5,
    "CacheTtlSeconds": 30
  }
}
```

## Contrato esperado do KMS
`GET {BaseUrl}{KeysEndpointPath}`
```json
{
  "currentKeyId": "kms-key-v2",
  "keys": [
    { "keyId": "kms-key-v1", "base64Key": "..." },
    { "keyId": "kms-key-v2", "base64Key": "..." }
  ]
}
```

`POST {BaseUrl}{RotateEndpointPath}`
```json
{ "keyId": "kms-key-v2" }
```

## Notas de segurança
- Não guardar `ApiKey` em appsettings de produção; usar secret store/variável de ambiente.
- `CacheTtlSeconds` deve ser curto (15-60s) para reduzir janela de exposição em memória.
- Chaves válidas para AES-GCM: 16, 24 ou 32 bytes.

## Validação operacional
1. `GET /ops/key-provider` retorna `Mode=ProdKms` e `CurrentKeyId`.
2. `GET /debug/key-provider` retorna `KeyLength` válida.
3. Se `RotateEndpointPath` configurado, `POST /ops/key-provider/rotate` troca `CurrentKeyId`.
