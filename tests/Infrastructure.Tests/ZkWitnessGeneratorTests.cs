using System.Security.Cryptography;
using System.Text;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Xunit;

namespace Infrastructure.Tests;

public sealed class ZkWitnessGeneratorTests
{
    [Fact]
    public void Generate_ShouldProduceDeterministicWitness()
    {
        var generator = CreateWitnessGenerator();

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
        var generator = CreateWitnessGenerator();

        var request = new PreimageRequest(
            Secret: "abc",
            HashPublic: "not-valid-hash",
            ClientId: "zk-client",
            Nonce: "nonce-xyz");

        var ex = Assert.Throws<InvalidOperationException>(() => generator.Generate(request));
        Assert.Contains("hashPublic", ex.Message);
    }

    private static IZkWitnessGenerator CreateWitnessGenerator()
    {
        var infrastructureAssembly = typeof(Infrastructure.DependencyInjection).Assembly;
        var implementationType = infrastructureAssembly.GetType(
            "Infrastructure.Zk.Witness.DefaultZkWitnessGenerator",
            throwOnError: true)!;

        return (IZkWitnessGenerator)Activator.CreateInstance(implementationType, nonPublic: true)!;
    }
}
