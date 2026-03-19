using Api.IntegrationTests.Infrastructure;
using Application.Abstractions.Data;
using Infrastructure.Authentication.ActiveDirectory;
using Infrastructure.Data;
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
            services.RemoveAll<IConfigureOptions<AuthenticationOptions>>();
            services.RemoveAll<IPostConfigureOptions<AuthenticationOptions>>();

            _connection = new SqliteConnection("Data Source=:memory:");
            _connection.Open();

            services.AddSingleton(_connection);
            services.AddDbContext<ApplicationDbContext>((sp, options) =>
                options.UseSqlite(sp.GetRequiredService<SqliteConnection>()));
            services.AddScoped<IApplicationDbContext>(sp => sp.GetRequiredService<ApplicationDbContext>());

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
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _connection?.Dispose();
    }
}
