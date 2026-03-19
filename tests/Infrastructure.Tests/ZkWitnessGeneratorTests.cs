using System.Security.Cryptography;
using System.Text;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Infrastructure.Tests;

public sealed class ZkWitnessGeneratorTests
{
    [Fact]
    public void Generate_ShouldProduceDeterministicWitness()
    {
        using var serviceProvider = BuildServiceProvider();
        var generator = serviceProvider.GetRequiredService<IZkWitnessGenerator>();

        const string secret = "witness-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashHex = Convert.ToHexString(hashBytes).ToLowerInvariant();
        var request = new PreimageRequest(
            Secret: secret,
            HashPublic: hashHex,
            ClientId: "zk-client",
            Nonce: "nonce-123");

        var witness = generator.Generate(request);

        Assert.Equal(Convert.ToBase64String(Encoding.UTF8.GetBytes(secret)), witness.SecretBase64);
        Assert.Equal(Convert.ToBase64String(hashBytes), witness.HashPublicBase64);
        Assert.Equal(Convert.ToBase64String(hashBytes), witness.SecretSha256Base64);
        Assert.Equal("zk-client", witness.ClientId);
        Assert.Equal("nonce-123", witness.Nonce);
        Assert.Equal("sha256-preimage-v1", witness.CircuitId);
        Assert.Equal(1, witness.Version);
    }

    [Fact]
    public void Generate_WithInvalidHashFormat_ShouldThrow()
    {
        using var serviceProvider = BuildServiceProvider();
        var generator = serviceProvider.GetRequiredService<IZkWitnessGenerator>();

        var request = new PreimageRequest(
            Secret: "abc",
            HashPublic: "not-valid-hash",
            ClientId: "zk-client",
            Nonce: "nonce-xyz");

        var ex = Assert.Throws<InvalidOperationException>(() => generator.Generate(request));
        Assert.Contains("hashPublic", ex.Message);
    }

    private static ServiceProvider BuildServiceProvider()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:Secret"] = "01234567890123456789012345678901",
                ["ZkBackend:LocalHmacKey"] = "test-zk-key"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddInfrastructure(config);
        return services.BuildServiceProvider();
    }
}
