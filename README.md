# Vault API

API ASP.NET Core (net10.0) organizada em camadas (Domain, Application, Infrastructure, Shared, Api) seguindo Clean Architecture. Suporta autenticação JWT e Windows (Negotiate/NTLM via HTTP.sys), persistência PostgreSQL via EF Core e observabilidade com Serilog/Seq.

## Requisitos
- .NET SDK 10.0.x (Windows, HTTP.sys)
- PostgreSQL 14+ (padrão usa `localhost:5432`)
- Ferramentas EF Core CLI: `dotnet tool install --global dotnet-ef`
- Opcional: Seq em `http://localhost:4452` para logs estruturados

## Configuração
1) Ajuste `Api/appsettings.Development.json`:
   - `ConnectionStrings:Database` para o seu PostgreSQL
   - `Jwt:Secret`, `Issuer`, `Audience` (não use `CHANGE_ME` em produção)
   - Opcional: URL do Seq em `Serilog:WriteTo:Seq:Args:ServerUrl`
2) Variáveis de ambiente também são aceitas (ASP.NET Core sobrescreve appsettings).

## Build e restauração
```pwsh
dotnet restore
dotnet build
```

## Migrações e banco
- Aplicar migrações existentes:
```pwsh
dotnet ef database update --project Infrastructure/Infrastructure.csproj --startup-project Api/Api.csproj
```
- Criar nova migração (exemplo):
```pwsh
dotnet ef migrations add <Nome> --project Infrastructure/Infrastructure.csproj --startup-project Api/Api.csproj
```

## Execução
```pwsh
dotnet run --project Api/Api.csproj
```
- Perfis em `launchSettings.json` expõem `http://localhost:5065` (http) e `https://localhost:7205` (https).
- Em Development o Swagger UI fica em `/swagger`.
- Autenticação: esquema híbrido `BearerOrNegotiate` seleciona JWT (Authorization: Bearer) ou Windows Negotiate automaticamente.

## Principais componentes
- `Api/Program.cs`: host HTTP.sys, Serilog, swagger, registro de endpoints.
- `Application`: casos de uso e contratos (ex.: autenticação, computadores).
- `Domain`: entidades e regras (`Users`, `Computers`, `KillSwitch`).
- `Infrastructure`: EF Core + PostgreSQL, JWT issuance, AD group authorization.
- `Shared`: tipos base (`Result`, `Entity`, `IDomainEvent`, `IDateTimeProvider`).

## Endpoints úteis (resumo)
- `POST /users/authenticate` e `POST /users/login`: fluxo de autenticação/token.
- `GET /users/user-groups`: retorna grupos (via AD provider).
- `GET /users/time-debug`: data/hora do servidor.
- `POST /computers/register`: registro de computador.
- `GET /diagnostics/auth-debug`: informações de autenticação atual.

## Testes
Nenhum projeto de teste incluso. Recomenda-se adicionar testes de unidade para Application/Domain e testes de integração para endpoints críticos.

## Estrutura de pastas
- `Api/` (Presentation)
- `Application/` (Use cases & contracts)
- `Domain/` (Entidades/regras)
- `Infrastructure/` (Banco, auth, services)
- `Shared/` (tipos compartilhados)
