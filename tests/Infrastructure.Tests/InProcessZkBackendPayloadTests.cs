using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Infrastructure.Zk;
using Infrastructure.Zk.Backends;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace Infrastructure.Tests;

public sealed class InProcessZkBackendPayloadTests
{
    [Fact]
    public async Task Prove_ShouldNotIncludeSecretInSerializedPayload()
    {
        var backend = CreateBackend();
        const string secret = "my-super-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);

        var request = new PreimageRequest(secret, hashBase64, "client-1", "nonce-1");
        var result = await backend.ProveAsync(request, CancellationToken.None);
        var json = Encoding.UTF8.GetString(result.Proof);

        Assert.DoesNotContain("SecretBase64", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SecretSha256Base64", json, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(secret)), json, StringComparison.Ordinal);
        Assert.Contains("\"SchemaVersion\":1", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_ShouldAcceptProofWithoutSecretInPayload()
    {
        var backend = CreateBackend();
        const string secret = "another-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);

        var proveRequest = new PreimageRequest(secret, hashBase64, "client-2", "nonce-2");
        var prove = await backend.ProveAsync(proveRequest, CancellationToken.None);
        var verifyRequest = new VerificationRequest(
            Proof: Convert.ToBase64String(prove.Proof),
            HashPublic: hashBase64,
            ClientId: "client-2",
            Nonce: "nonce-2");

        var ok = await backend.VerifyAsync(verifyRequest, CancellationToken.None);
        Assert.True(ok);
    }

    [Fact]
    public async Task Verify_ShouldRejectUnsupportedSchemaVersion()
    {
        var backend = CreateBackend();
        const string secret = "schema-version-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);

        var proveRequest = new PreimageRequest(secret, hashBase64, "client-3", "nonce-3");
        var prove = await backend.ProveAsync(proveRequest, CancellationToken.None);

        using var doc = JsonDocument.Parse(prove.Proof);
        var payload = doc.RootElement;
        var witness = payload.GetProperty("Witness");
        var macBase64 = payload.GetProperty("MacBase64").GetString()!;

        var tampered = new
        {
            SchemaVersion = 999,
            Witness = new
            {
                HashPublicBase64 = witness.GetProperty("HashPublicBase64").GetString(),
                ClientId = witness.GetProperty("ClientId").GetString(),
                Nonce = witness.GetProperty("Nonce").GetString(),
                CircuitId = witness.GetProperty("CircuitId").GetString(),
                Version = witness.GetProperty("Version").GetInt32()
            },
            MacBase64 = macBase64
        };

        var tamperedBytes = JsonSerializer.SerializeToUtf8Bytes(tampered);
        var verifyRequest = new VerificationRequest(
            Proof: Convert.ToBase64String(tamperedBytes),
            HashPublic: hashBase64,
            ClientId: "client-3",
            Nonce: "nonce-3");

        var ok = await backend.VerifyAsync(verifyRequest, CancellationToken.None);
        Assert.False(ok);
    }

    private static InProcessZkBackend CreateBackend()
    {
        var options = Options.Create(new ZkBackendOptions
        {
            LocalHmacKey = "zk-test-key-012345678901234567890123"
        });

        return new InProcessZkBackend(
            options,
            new FakeHostEnvironment("Development"),
            new FakeWitnessGenerator());
    }

    private sealed class FakeWitnessGenerator : IZkWitnessGenerator
    {
        public ZkWitness Generate(PreimageRequest request)
        {
            var secretBytes = Encoding.UTF8.GetBytes(request.Secret);
            var secretHash = SHA256.HashData(secretBytes);
            return new ZkWitness(
                SecretBase64: Convert.ToBase64String(secretBytes),
                HashPublicBase64: Convert.ToBase64String(secretHash),
                SecretSha256Base64: Convert.ToBase64String(secretHash),
                ClientId: request.ClientId,
                Nonce: request.Nonce,
                CircuitId: "sha256-preimage-v1",
                Version: 1);
        }
    }

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
