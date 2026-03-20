using Application.Abstractions.Security;
using Infrastructure;
using Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Infrastructure.Tests;

public sealed class NonceStoreRegistrationTests
{
    [Fact]
    public void AddInfrastructure_ShouldRegisterInMemoryNonceStore_WhenProviderIsDefault()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
            ["Jwt:Issuer"] = "issuer",
            ["Jwt:Audience"] = "audience",
            ["Jwt:Secret"] = "this-is-a-long-enough-jwt-secret-for-tests",
            ["Jwt:ExpirationMinutes"] = "60",
            ["Authentication:Kerberos:Enabled"] = "false",
            ["Authentication:Ldap:Enabled"] = "false",
            ["KeyProvider:Mode"] = "Dev",
            ["KeyProvider:Dev:KeyId"] = "dev-key-v1",
            ["KeyProvider:Dev:Base64Key"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            ["NonceStore:Enabled"] = "true",
            ["NonceStore:TtlSeconds"] = "300",
            ["NonceStore:MaxEntries"] = "1000"
        });

        services.AddInfrastructure(configuration);
        using var serviceProvider = services.BuildServiceProvider();

        var nonceStore = serviceProvider.GetRequiredService<INonceStore>();

        Assert.IsType<InMemoryNonceStore>(nonceStore);
    }

    [Fact]
    public void AddInfrastructure_ShouldRegisterPostgresNonceStore_WhenConfigured()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
            ["Jwt:Issuer"] = "issuer",
            ["Jwt:Audience"] = "audience",
            ["Jwt:Secret"] = "this-is-a-long-enough-jwt-secret-for-tests",
            ["Jwt:ExpirationMinutes"] = "60",
            ["Authentication:Kerberos:Enabled"] = "false",
            ["Authentication:Ldap:Enabled"] = "false",
            ["KeyProvider:Mode"] = "Dev",
            ["KeyProvider:Dev:KeyId"] = "dev-key-v1",
            ["KeyProvider:Dev:Base64Key"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            ["NonceStore:Provider"] = NonceStoreProviders.Postgres,
            ["NonceStore:Enabled"] = "true",
            ["NonceStore:TtlSeconds"] = "300",
            ["NonceStore:MaxEntries"] = "1000"
        });

        services.AddInfrastructure(configuration);
        using var serviceProvider = services.BuildServiceProvider();

        var nonceStore = serviceProvider.GetRequiredService<INonceStore>();

        Assert.IsType<PostgresNonceStore>(nonceStore);
    }

    private static IConfiguration BuildConfiguration(IReadOnlyDictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }
}
