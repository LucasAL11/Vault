using Api.IntegrationTests.Infrastructure;
using Application.Abstractions.Data;
using Application.Abstractions.Security;
using Infrastructure.Authentication.ActiveDirectory;
using Infrastructure.Data;
using Infrastructure.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Api.IntegrationTests.Infrastructure;

public sealed class ApiTestFactory : WebApplicationFactory<Api.Program>
{
    public static readonly Guid VaultId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private SqliteConnection? _connection;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<ApplicationDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<ApplicationDbContext>>();
            services.RemoveAll<ApplicationDbContext>();
            services.RemoveAll<IApplicationDbContext>();
            services.RemoveAll<INonceStore>();
            services.RemoveAll<IConfigureOptions<AuthenticationOptions>>();
            services.RemoveAll<IPostConfigureOptions<AuthenticationOptions>>();

            _connection = new SqliteConnection("Data Source=:memory:");
            _connection.Open();

            services.AddSingleton(_connection);
            services.AddDbContext<ApplicationDbContext>((sp, options) =>
                options.UseSqlite(sp.GetRequiredService<SqliteConnection>()));
            services.AddScoped<IApplicationDbContext>(sp => sp.GetRequiredService<ApplicationDbContext>());
            services.AddSingleton<INonceStore, InMemoryNonceStore>();

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                    options.DefaultForbidScheme = "Test";
                    options.DefaultScheme = "Test";
                })
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

            services.AddSingleton<IAuthorizationHandler, AllowAllAdGroupAuthorizationHandler>();
        });
    }

    public async Task EnsureInitializedAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureCreatedAsync();

        if (!await db.Vaults.AnyAsync(x => x.Id == VaultId))
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO vault (
                    Id,
                    Name,
                    Slug,
                    Description,
                    TenantId,
                    Environment,
                    Status,
                    "Group",
                    KeyReference,
                    RotationPeriod,
                    LastRotation,
                    RequireMultiFactorAuthentication,
                    AllowMultiFactorAuthentication,
                    RowVersion,
                    Owner,
                    EncryptionPolicy
                )
                VALUES (
                    {VaultId},
                    {"Vault Integracao"},
                    {"vault-integracao"},
                    {"Vault para testes de integracao."},
                    {"tenant-test"},
                    {0},
                    {0},
                    {"Administradores de Chaves"},
                    {(string?)null},
                    {0},
                    {(DateTimeOffset?)null},
                    {false},
                    {false},
                    {new byte[] { 1 }},
                    {"integration.user"},
                    {0}
                );
                """);
        }
        else
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE vault
                SET
                    Status = {0},
                    "Group" = {"Administradores de Chaves"}
                WHERE Id = {VaultId};
                """);
        }

        var adMapId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        if (!await db.ADMaps.AnyAsync(x => x.Id == adMapId))
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO vault_ad_map (
                    Id,
                    VaultId,
                    GroupId,
                    Permission,
                    IsActive,
                    CreatedAt,
                    RowVersion
                )
                VALUES (
                    {adMapId},
                    {VaultId},
                    {"Administradores de Chaves"},
                    {3},
                    {true},
                    {DateTimeOffset.UtcNow},
                    {new byte[] { 1 }}
                );
                """);
        }
        else
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE vault_ad_map
                SET
                    VaultId = {VaultId},
                    GroupId = {"Administradores de Chaves"},
                    Permission = {3},
                    IsActive = {true}
                WHERE Id = {adMapId};
                """);
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _connection?.Dispose();
    }
}
