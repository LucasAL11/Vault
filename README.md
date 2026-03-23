# WebApplication1 - Guia Base de Trabalho

Este README e a base oficial para qualquer manutencao, feature ou investigacao neste repositorio.
Antes de codar, siga as secoes de "Fluxo de trabalho" e "Checklist".

## 1) Objetivo do projeto
API ASP.NET Core com arquitetura em camadas:
- `Api` (entrada HTTP, endpoints, middleware)
- `Application` (casos de uso, comandos/queries, contratos)
- `Domain` (entidades e regras de negocio)
- `Infrastructure` (EF Core/PostgreSQL, autenticacao, integracoes externas)
- `Shared` (tipos base: `Result`, `Entity`, `IDomainEvent`, etc.)

Principais capacidades atuais:
- Registro de computadores
- Autenticacao hibrida (`JWT` ou `Windows/Negotiate`)
- Fluxo de segredo com challenge/proof HMAC e auditoria
- Kill switch por grupo autorizado

## 2) Stack tecnica
- .NET SDK: `10.0`
- ASP.NET Core: `net10.0-windows` no projeto `Api`
- Banco: PostgreSQL + EF Core + Npgsql
- Auth: JWT + Negotiate (policy scheme `BearerOrNegotiate`)
- Observabilidade: Serilog (Console e Seq)
- Swagger: habilitado em `Development`
- Versionamento de contratos: `v1` por rota e OpenAPI

## 3) Estrutura da solucao
`WebApplication1.sln` contem:
- `Api/Api.csproj`
- `Application/Application.csproj`
- `Domain/Domain.csproj`
- `Infrastructure/Infrastructure.csproj`
- `Shared/Shared.csproj`

## 4) Configuracao local
### 4.1 Requisitos
- .NET SDK 10 instalado
- PostgreSQL em execucao
- (Opcional) Seq em `http://localhost:4452`
- Ferramenta EF CLI:
```powershell
dotnet tool install --global dotnet-ef
```

### 4.2 Arquivos de configuracao
- Base: `Api/appsettings.json`
- Desenvolvimento: `Api/appsettings.Development.json`
- Launch profile: `Api/Properties/launchSettings.json`

Ajustar no minimo:
- `ConnectionStrings:Database`
- `Jwt:Issuer`, `Jwt:Audience`, `Jwt:Secret`
- `KeyProvider` (`Mode=Dev` para local; `Mode=Prod` com `APP_KEY_ID` e `APP_KEY_BASE64`)
- `KillSwitch` (se necessario)

## 5) Comandos do dia a dia
### 5.1 Restore e build
```powershell
dotnet restore
dotnet build WebApplication1.sln
```

### 5.2 Rodar API
```powershell
dotnet run --project Api/Api.csproj
```

Perfis locais configurados:
- `http://localhost:5065`
- `https://localhost:7205`

Swagger (apenas Development):
- `http://localhost:5065/swagger`
- docs: `v1`

### 5.3 Banco de dados e migracoes
Aplicar migracoes:
```powershell
dotnet ef database update --project Infrastructure/Infrastructure.csproj --startup-project Api/Api.csproj
```

Criar migracao nova:
```powershell
dotnet ef migrations add <NomeDaMigracao> --project Infrastructure/Infrastructure.csproj --startup-project Api/Api.csproj
```

## 6) Endpoints mapeados hoje
- `POST /users`
- `GET /users/{id}`
- `GET /users/groups`
- `GET /users/ad-group-example`
- `POST /computers`
- `PUT /vaults/{vaultId}/secrets/{name}`
- `GET /vaults/{vaultId}/secrets`
- `GET /vaults/{vaultId}/secrets/{name}`
- `GET /vaults/{vaultId}/secrets/{name}/versions`
- `POST /vaults/{vaultId}/secrets/{name}/request`
- `GET /vaults/{vaultId}/secrets/{name}/audit`
- `GET /debug/auth`
- `GET /debug/key-provider`
- `GET /ops/key-provider`
- `POST /ops/key-provider/rotate`
- `POST /ops/key-provider/re-encrypt`
- `GET /debug/time`
- `GET /ops/killswitch`
- `POST /ops/killswitch`
- `GET /ops/killswitch/denylist`
- `POST /ops/killswitch/denylist`
- `DELETE /ops/killswitch/denylist/{username}`

Obs.: `Api/WebApplication1.http` contem um roteiro de smoke test para os endpoints principais.

## 7) Fluxo de trabalho para qualquer nova tarefa
Sempre seguir esta ordem:
1. Confirmar objetivo funcional (o que muda para o usuario/API).
2. Identificar camada correta da mudanca:
   - Regra -> `Domain`
   - Caso de uso/orquestracao -> `Application`
   - Persistencia/auth/integracao -> `Infrastructure`
   - Contrato HTTP -> `Api`
3. Implementar mudanca mantendo contrato de `Result` e tratamento de erro.
4. Validar build e impacto nos endpoints.
5. Atualizar este README se comportamento/fluxo mudar.

## 8) Padrao para adicionar feature
1. `Domain`: criar/ajustar entidade, value objects e erros.
2. `Application`: criar comando/query + handler + contratos.
3. `Infrastructure`: implementar adaptadores necessarios (db/auth/http client).
4. `Api`: expor endpoint via classe que implementa `IEndpoint`.
5. Registrar dependencias via `DependencyInjection` da camada.
6. Testar fluxo ponta a ponta localmente.

## 9) Checklist antes de encerrar uma tarefa
- Build da solucao executa sem erros.
- Config local necessaria foi documentada.
- Endpoint novo/alterado foi validado manualmente.
- Migracao criada (quando ha alteracao de schema).
- Sem segredo hardcoded em codigo fonte.
- README atualizado quando houver mudanca estrutural.

## 10) Convencoes do repositorio
- Endpoints sao descobertos automaticamente por reflection (`IEndpoint` + `AddEndpoints`).
- Pipeline principal: `UseAuthentication` -> `KillSwitchMiddleware` -> `UseAuthorization`.
- Auth default: policy scheme `HybridAuth`.
- Contratos versionados por rota: `/api/v1/...` (legacy sem prefixo mantido para compatibilidade, fora do Swagger).
- Logs estruturados com Serilog.
- Key provider com selecao por ambiente (`DevKeyProvider`/`ProdKeyProvider`).
- Fluxo oficial do MVP: `POST /auth/challenge` -> `POST /vaults/{vaultId}/secrets/{name}/request` com contrato `v1` e `proof` HMAC.
- Roadmap tecnico oficial do MVP sem ZK: `docs/runbooks/mvp-sem-zk-roadmap.md`.

## 11) Pontos de atencao atuais
- Decisao oficial de escopo em 2026-03-23: MVP segue padrao sem ZK.
- Rotas ZK (`/Cryptography/hash`, `/Cryptography/zk`, `/Cryptography/verify`) foram removidas do runtime.
- Todo item de roadmap dependente de prover ZK (in-process ou externo) permanece fora do escopo do MVP.
- Documentacao de ZK foi mantida apenas como referencia historica nos runbooks de legado.
- Se o `KillSwitch` estiver `Enabled`, apenas grupo autorizado passa.
- O kill switch pode ser operado em runtime via `/ops/killswitch` (sem restart), por usuario autenticado pertencente ao `AllowedGroup`.
- A denylist temporaria pode bloquear usuarios especificos por janela de tempo via `/ops/killswitch/denylist`.
- `GET /vaults/{vaultId}/secrets/{name}` retorna apenas metadados (sem valor em claro), com autorizacao por policy AD do grupo do vault e auditoria em log.
- `GET /vaults/{vaultId}/secrets` retorna lista paginada de metadados com filtros por `name`/`status` e ordenacao estavel.
- `POST /vaults/{vaultId}/secrets/{name}/request` exige `proof` HMAC vinculado a nonce (`audience=vault.secret.request`) para liberar valor em claro.
- Contrato obrigatorio `v1` para `POST /vaults/{vaultId}/secrets/{name}/request`: `contractVersion`, `reason`, `ticket`, `clientId`, `nonce`, `issuedAt`, `proof`.
- Compatibilidade legada temporaria: `ticketId` e `issuedAtUtc` ainda sao aceitos como alias de `ticket` e `issuedAt`.
- Endpoints de leitura de segredo possuem rate limit e retornam `429` em abuso.
- Pre-requisitos de autenticacao AD/Kerberos/LDAP/OIDC estao em `docs/runbooks/ad-prerequisitos.md`.

Exemplo de payload do contrato `v1`:

```json
{
  "contractVersion": "v1",
  "reason": "Incidente em producao",
  "ticket": "INC-1234",
  "clientId": "local-dev-client",
  "nonce": "<base64url>",
  "issuedAt": "2026-03-23T12:00:00Z",
  "proof": "<hmac-sha256-base64url>"
}
```

## 12) Roadmap tecnico do MVP sem ZK
Roadmap atualizado e oficial:
- `docs/runbooks/mvp-sem-zk-roadmap.md`

Diretriz de escopo:
- ZK (`/Cryptography/*`, `Infrastructure/Zk/*`) e legado tecnico, nao objetivo do MVP.

## 13) Quando usar este README
Use este arquivo como contrato de equipe:
- Toda nova tarefa parte daqui.
- Toda mudanca de arquitetura/execucao deve refletir aqui no mesmo PR/commit.
