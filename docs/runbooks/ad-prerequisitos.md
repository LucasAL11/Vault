# Runbook: Pré-requisitos AD (Kerberos + LDAP + OIDC)

## Objetivo
Garantir que o ambiente esteja pronto para autenticação/autorização AD na API com estratégia híbrida.

## Escopo
Este runbook cobre os pré-requisitos para:
- Kerberos (`Negotiate`) para autenticação integrada.
- LDAP/AD para resolução de grupos (fallback server-side).
- OIDC (Microsoft Entra ID/Azure AD ou IdP compatível) para Bearer corporativo.

## Estratégia primária da API
- Esquema padrão: `HybridAuth`.
- Fluxo:
1. Se houver `Authorization: Bearer`, a API roteia para `OidcJwt` (quando issuer/authority bater) ou `LocalJwt`.
2. Sem Bearer, a API usa `Negotiate` (Kerberos), quando habilitado.
3. Na autorização por grupo, usa claims -> `UserContext.Groups` -> fallback LDAP/AD.

## Pré-requisitos gerais
- API hospedada em Windows com acesso de rede ao AD.
- DNS e sincronismo de horário (NTP) corretos entre cliente, servidor da API e controladores de domínio.
- Firewall liberando:
  - Kerberos: TCP/UDP 88.
  - LDAP: TCP 389 (ou 636 para LDAPS, recomendado).
  - Global Catalog (opcional): 3268/3269.
- Conta de execução da API com permissão para consulta de usuários/grupos no AD.

## Pré-requisitos Kerberos (Negotiate)
- Servidor da API ingressado no domínio (ou trust válido).
- SPN registrado para o host da API na conta de serviço correta.
- Navegador cliente configurado para autenticação integrada no host da API.
- `Authentication:Kerberos:Enabled = true`.

Exemplo de configuração:
```json
"Authentication": {
  "Kerberos": { "Enabled": true }
}
```

## Pré-requisitos LDAP/AD (fallback de grupos)
- `Authentication:Ldap:Enabled = true`.
- Definir `Domain` quando necessário (multi-domain/host dedicado).
- Definir `Container` quando quiser restringir escopo de busca.
- Grupo usado em policy deve mapear para nome resolvível (`sAMAccountName` ou equivalente).

Exemplo de configuração:
```json
"Authentication": {
  "Ldap": {
    "Enabled": true,
    "Domain": "corp.local",
    "Container": "OU=Users,DC=corp,DC=local"
  }
}
```

## Pré-requisitos OIDC (opcional)
- Registrar API no IdP com `audience`/`issuer` corretos.
- Garantir emissão de claims de grupos/roles (ou suportar overage com fallback LDAP).
- `Authentication:Oidc:Enabled = true` e parâmetros preenchidos.

Exemplo de configuração:
```json
"Authentication": {
  "Oidc": {
    "Enabled": true,
    "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "Issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "Audience": "api://<app-id>",
    "RequireHttpsMetadata": true,
    "RoleClaimType": "groups",
    "NameClaimType": "name"
  }
}
```

## Checklist de validação rápida
1. Suba a API com as configurações acima.
2. Acesse um endpoint protegido sem Bearer:
- Esperado: challenge `Negotiate` seguido de autenticação integrada (se cliente no domínio).
3. Chame endpoint protegido com Bearer OIDC válido:
- Esperado: `200` se `iss`/`aud` válidos.
4. Valide grupo AD em endpoint com policy `AdGroup:*`:
- Esperado: `200` para membro do grupo e `403` para não membro.
5. Simule indisponibilidade AD/LDAP:
- Esperado: comportamento fail-closed (`403`) sem queda da API.

## Troubleshooting
### `401 Unauthorized`
- Bearer inválido (`iss`, `aud`, assinatura, expiração).
- Kerberos sem SPN correto ou cliente fora da zona de autenticação integrada.

### `403 Forbidden`
- Usuário autenticado, mas sem grupo exigido.
- Grupo não resolvido por claim e fallback LDAP não encontrou associação.

### Prompt de credencial Windows no navegador
- Comportamento esperado quando não há Bearer e `Negotiate` está habilitado.

## Observações
- Em Linux containers, validar suporte de Kerberos/Negotiate antes de produção.
- Para produção, preferir LDAPS e restringir escopo de busca (`Container`) para reduzir latência.
