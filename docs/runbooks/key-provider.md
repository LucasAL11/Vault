# Runbook: Key Provider (Dev e Prod)

## Objetivo
Operar o `IKeyProvider` com segurança nos modos `Dev` e `Prod`, validando carregamento de chave, troca de modo e rollback.

## Escopo
- Configuração do modo `Dev`
- Configuração do modo `Prod`
- Validação via endpoint de diagnóstico
- Rotação de chave em produção
- Troubleshooting de erros de inicialização

## Referências
- Config: `Api/appsettings.json` e `Api/appsettings.Development.json`
- Variáveis de ambiente (produção): `APP_KEY_ID`, `APP_KEY_BASE64`, `APP_KEY_CURRENT_ID`
- Endpoint de validação: `GET /debug/key-provider`
- Endpoints operacionais:
  - `GET /ops/key-provider`
  - `POST /ops/key-provider/rotate`
  - `POST /ops/key-provider/re-encrypt`

## Pré-requisitos
- API em execução
- Token JWT válido para endpoint protegido
- Chave em Base64 com no mínimo 32 bytes

## Modo Dev
1. Defina no appsettings:
```json
"KeyProvider": {
  "Mode": "Dev",
  "Dev": {
    "KeyId": "dev-local-key-v1",
    "Base64Key": "<base64-32bytes+>"
  }
}
```
2. Inicie/reinicie a API.
3. Valide:
```http
GET /debug/key-provider
Authorization: Bearer <token>
```
Esperado: `200`, com `KeyId` e `KeyLength >= 32`.

## Modo Prod
1. Defina no appsettings:
```json
"KeyProvider": {
  "Mode": "Prod",
  "OperatorsGroup": "Administradores de Chaves",
  "Prod": {
    "CurrentKeyId": "prod-key-v1",
    "Keys": [
      { "KeyId": "prod-key-v1", "Base64Key": "<base64-32bytes+>" },
      { "KeyId": "prod-key-v2", "Base64Key": "<base64-32bytes+>" }
    ]
  }
}
```
2. Defina variáveis de ambiente no host:
```powershell
$env:APP_KEY_ID="prod-key-v1"
$env:APP_KEY_BASE64="<base64-32bytes+>"
```
3. Inicie/reinicie a API.
4. Valide:
```http
GET /debug/key-provider
Authorization: Bearer <token>
```
Esperado: `200`, com `KeyId=prod-key-v1` e `KeyLength >= 32`.

## Rotação de Chave (Prod)
1. Gere nova chave e novo `KeyId` (`prod-key-v2`).
2. Adicione a nova chave no key ring de produção (`Prod:Keys`), mantendo a antiga.
3. Faça rotação em runtime:
```http
POST /ops/key-provider/rotate
Authorization: Bearer <token>
Content-Type: application/json

{
  "keyId": "prod-key-v2"
}
```
4. Valide:
   - `GET /ops/key-provider` deve retornar `CurrentKeyId = prod-key-v2`
   - `GET /debug/key-provider` deve mostrar o novo `KeyId`
5. Re-encrypt das versoes antigas para a chave nova:
```http
POST /ops/key-provider/re-encrypt
Authorization: Bearer <token>
Content-Type: application/json

{
  "vaultId": "<guid-do-vault>",
  "secretName": "DB_PASSWORD",
  "includeRevoked": false,
  "includeExpired": false
}
```
6. Validar retorno `RotatedCount > 0` quando havia versoes em chave antiga.
7. Monitore erros por 15 minutos.

## Rollback
1. Execute nova rotação para a chave anterior (`prod-key-v1`) via endpoint.
2. Execute `POST /ops/key-provider/re-encrypt` para voltar dados para a chave anterior.
3. Valide novamente em `GET /ops/key-provider` e `GET /debug/key-provider`.

## Troubleshooting
### Erro: key id ausente
- Mensagem esperada: `Production current key id is missing`.
- Ação: definir `APP_KEY_CURRENT_ID` ou `KeyProvider:Prod:CurrentKeyId`.

### Erro: key ausente
- Mensagem esperada: `Current production key ... is not present in ...`.
- Ação: incluir a chave correspondente em `KeyProvider:Prod:Keys` ou via `APP_KEY_ID` + `APP_KEY_BASE64`.

### Erro: key inválida
- Mensagem esperada: `key is not valid base64` ou `must have at least 32 bytes`.
- Ação: gerar Base64 válido com comprimento mínimo exigido.

## Checklist Operacional
- Modo correto configurado (`Dev` ou `Prod`)
- Chave carregada com `KeyLength >= 32`
- Endpoint de diagnóstico validado
- Sem erro de inicialização relacionado ao `KeyProvider`
