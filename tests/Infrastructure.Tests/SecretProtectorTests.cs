using System.Text;
using System.Security.Cryptography;
using Application.Abstractions.Security;
using Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Infrastructure.Tests;

public class SecretProtectorTests
{
    [Fact]
    public async Task ProtectAndUnprotect_WithDevKeyProvider_ShouldRoundTrip()
    {
        using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["KeyProvider:Mode"] = "Dev",
            ["KeyProvider:Dev:KeyId"] = "dev-test-key-v1",
            ["KeyProvider:Dev:Base64Key"] = ToBase64("01234567890123456789012345678901")
        });

        var protector = serviceProvider.GetRequiredService<ISecretProtector>();

        const string plaintext = "Senha@SuperSecreta!";
        var protectedSecret = await protector.ProtectAsync(plaintext);

        Assert.NotEmpty(protectedSecret.CipherText);
        Assert.Equal(12, protectedSecret.Nonce.Length);
        Assert.NotEqual(plaintext, Encoding.UTF8.GetString(protectedSecret.CipherText));

        var unprotected = await protector.UnprotectAsync(protectedSecret);
        Assert.Equal(plaintext, unprotected);
    }

    [Fact]
    public async Task Unprotect_WithDifferentAadContext_ShouldFail()
    {
        using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["KeyProvider:Mode"] = "Dev",
            ["KeyProvider:Dev:KeyId"] = "dev-test-key-v1",
            ["KeyProvider:Dev:Base64Key"] = ToBase64("01234567890123456789012345678901")
        });

        var protector = serviceProvider.GetRequiredService<ISecretProtector>();
        var correctContext = new SecretProtectionContext(
            VaultId: Guid.Parse("11111111-1111-1111-1111-111111111111"),
            SecretId: Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Version: 1);

        var wrongContext = new SecretProtectionContext(
            VaultId: Guid.Parse("11111111-1111-1111-1111-111111111111"),
            SecretId: Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Version: 2);

        var protectedSecret = await protector.ProtectAsync("valor-com-aad", correctContext);

        var exception = await Record.ExceptionAsync(async () =>
            await protector.UnprotectAsync(protectedSecret, wrongContext));

        Assert.NotNull(exception);
        Assert.IsAssignableFrom<CryptographicException>(exception);
    }

    [Fact]
    public async Task Unprotect_WithUnknownKeyId_ShouldThrow()
    {
        using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["KeyProvider:Mode"] = "Dev",
            ["KeyProvider:Dev:KeyId"] = "dev-test-key-v1",
            ["KeyProvider:Dev:Base64Key"] = ToBase64("01234567890123456789012345678901")
        });

        var protector = serviceProvider.GetRequiredService<ISecretProtector>();
        var protectedSecret = new ProtectedSecret(
            CipherText: RandomBytes(32),
            Nonce: RandomBytes(12),
            KeyId: "missing-key-v9");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await protector.UnprotectAsync(protectedSecret));

        Assert.Contains("was not found", exception.Message);
    }

    [Fact]
    public async Task ProtectBeforeAndAfterRotation_WithProdKeyRing_ShouldDecryptBothVersions()
    {
        var originalKeyId = Environment.GetEnvironmentVariable("APP_KEY_ID");
        var originalKey = Environment.GetEnvironmentVariable("APP_KEY_BASE64");
        var originalCurrent = Environment.GetEnvironmentVariable("APP_KEY_CURRENT_ID");

        try
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", null);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", null);
            Environment.SetEnvironmentVariable("APP_KEY_CURRENT_ID", null);

            using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
            {
                ["KeyProvider:Mode"] = "Prod",
                ["KeyProvider:Prod:CurrentKeyId"] = "prod-key-v1",
                ["KeyProvider:Prod:Keys:0:KeyId"] = "prod-key-v1",
                ["KeyProvider:Prod:Keys:0:Base64Key"] = ToBase64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ["KeyProvider:Prod:Keys:1:KeyId"] = "prod-key-v2",
                ["KeyProvider:Prod:Keys:1:Base64Key"] = ToBase64("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            });

            var keyProvider = serviceProvider.GetRequiredService<IKeyProvider>();
            var protector = serviceProvider.GetRequiredService<ISecretProtector>();

            var oldVersion = await protector.ProtectAsync("valor-v1");
            await keyProvider.RotateCurrentKeyAsync("prod-key-v2");
            var newVersion = await protector.ProtectAsync("valor-v2");

            Assert.Equal("prod-key-v1", oldVersion.KeyId);
            Assert.Equal("prod-key-v2", newVersion.KeyId);

            var oldPlain = await protector.UnprotectAsync(oldVersion);
            var newPlain = await protector.UnprotectAsync(newVersion);

            Assert.Equal("valor-v1", oldPlain);
            Assert.Equal("valor-v2", newPlain);
        }
        finally
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", originalKeyId);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", originalKey);
            Environment.SetEnvironmentVariable("APP_KEY_CURRENT_ID", originalCurrent);
        }
    }

    private static ServiceProvider BuildServiceProvider(Dictionary<string, string?> overrides)
    {
        var baseConfig = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
            ["Jwt:Issuer"] = "test-issuer",
            ["Jwt:Audience"] = "test-audience",
            ["Jwt:Secret"] = "01234567890123456789012345678901",
            ["ZkBackend:LocalHmacKey"] = "test-zk-key"
        };

        foreach (var item in overrides)
        {
            baseConfig[item.Key] = item.Value;
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(baseConfig)
            .Build();

        var services = new ServiceCollection();
        services.AddInfrastructure(configuration);
        return services.BuildServiceProvider();
    }

    private static string ToBase64(string value)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static byte[] RandomBytes(int size)
    {
        var bytes = new byte[size];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }
}
