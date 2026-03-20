using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Numerics;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Application.Cryptography.Constraints;
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
        Assert.Contains("\"Ir\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Id\":\"sha256-preimage-r1cs\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Major\":1", json, StringComparison.Ordinal);
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

    [Fact]
    public async Task Verify_WithMalformedInputs_ShouldReturnFalse()
    {
        var backend = CreateBackend();

        var malformedRequest = new VerificationRequest(
            Proof: "%%%invalid-proof%%%",
            HashPublic: "%%%invalid-hash%%%",
            ClientId: "client-malformed",
            Nonce: "nonce-malformed");

        var ok = await backend.VerifyAsync(malformedRequest, CancellationToken.None);
        Assert.False(ok);
    }

    [Fact]
    public async Task Verify_ShouldRejectUnsupportedIrMajor()
    {
        var backend = CreateBackend();
        const string secret = "ir-major-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);

        var prove = await backend.ProveAsync(
            new PreimageRequest(secret, hashBase64, "client-ir-major", "nonce-ir-major"),
            CancellationToken.None);

        using var doc = JsonDocument.Parse(prove.Proof);
        var payload = doc.RootElement;
        var witness = payload.GetProperty("Witness");
        var ir = payload.GetProperty("Ir");

        var tampered = new
        {
            SchemaVersion = payload.GetProperty("SchemaVersion").GetInt32(),
            Ir = new
            {
                Id = ir.GetProperty("Id").GetString(),
                Major = 999,
                Minor = ir.GetProperty("Minor").GetInt32(),
                Patch = ir.GetProperty("Patch").GetInt32(),
                ConstraintSystem = ir.GetProperty("ConstraintSystem").GetString(),
                Curve = ir.GetProperty("Curve").GetString(),
                Field = ir.GetProperty("Field").GetString(),
                ConstraintHashBase64 = ir.GetProperty("ConstraintHashBase64").GetString()
            },
            Witness = new
            {
                HashPublicBase64 = witness.GetProperty("HashPublicBase64").GetString(),
                ClientId = witness.GetProperty("ClientId").GetString(),
                Nonce = witness.GetProperty("Nonce").GetString(),
                CircuitId = witness.GetProperty("CircuitId").GetString(),
                Version = witness.GetProperty("Version").GetInt32()
            },
            MacBase64 = payload.GetProperty("MacBase64").GetString()
        };

        var tamperedBytes = JsonSerializer.SerializeToUtf8Bytes(tampered);
        var ok = await backend.VerifyAsync(new VerificationRequest(
            Proof: Convert.ToBase64String(tamperedBytes),
            HashPublic: hashBase64,
            ClientId: "client-ir-major",
            Nonce: "nonce-ir-major"), CancellationToken.None);

        Assert.False(ok);
    }

    [Fact]
    public async Task Verify_ShouldAcceptLegacyProofWithoutIr_WhenLegacyMacIsValid()
    {
        var backend = CreateBackend();
        const string secret = "legacy-proof-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);
        const string clientId = "client-legacy";
        const string nonce = "nonce-legacy";

        var prove = await backend.ProveAsync(
            new PreimageRequest(secret, hashBase64, clientId, nonce),
            CancellationToken.None);

        using var doc = JsonDocument.Parse(prove.Proof);
        var payload = doc.RootElement;
        var witness = payload.GetProperty("Witness");
        var witnessHash = witness.GetProperty("HashPublicBase64").GetString()!;
        var circuitId = witness.GetProperty("CircuitId").GetString()!;
        var circuitVersion = witness.GetProperty("Version").GetInt32();
        var legacyMacBase64 = ComputeLegacyMacBase64(
            witnessHash,
            clientId,
            nonce,
            circuitId,
            circuitVersion);

        var legacyPayload = new
        {
            SchemaVersion = payload.GetProperty("SchemaVersion").GetInt32(),
            Witness = new
            {
                HashPublicBase64 = witnessHash,
                ClientId = clientId,
                Nonce = nonce,
                CircuitId = circuitId,
                Version = circuitVersion
            },
            MacBase64 = legacyMacBase64
        };

        var legacyProofBytes = JsonSerializer.SerializeToUtf8Bytes(legacyPayload);
        var ok = await backend.VerifyAsync(new VerificationRequest(
            Proof: Convert.ToBase64String(legacyProofBytes),
            HashPublic: hashBase64,
            ClientId: clientId,
            Nonce: nonce), CancellationToken.None);

        Assert.True(ok);
    }

    [Fact]
    public async Task Prove_WhenR1csValidationFails_ShouldThrow()
    {
        var backend = CreateBackend(validatorAlwaysSatisfied: false);
        const string secret = "r1cs-failure-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);

        var request = new PreimageRequest(secret, hashBase64, "client-r1cs", "nonce-r1cs");

        await Assert.ThrowsAsync<InvalidOperationException>(() => backend.ProveAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task Verify_WhenR1csValidationFails_ShouldReturnFalse()
    {
        var backendForProof = CreateBackend();
        const string secret = "verify-r1cs-secret";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashBase64 = Convert.ToBase64String(hashBytes);

        var proof = await backendForProof.ProveAsync(
            new PreimageRequest(secret, hashBase64, "client-r1cs-verify", "nonce-r1cs-verify"),
            CancellationToken.None);

        var backendForVerify = CreateBackend(validatorAlwaysSatisfied: false);
        var verifyRequest = new VerificationRequest(
            Proof: Convert.ToBase64String(proof.Proof),
            HashPublic: hashBase64,
            ClientId: "client-r1cs-verify",
            Nonce: "nonce-r1cs-verify");

        var ok = await backendForVerify.VerifyAsync(verifyRequest, CancellationToken.None);
        Assert.False(ok);
    }

    private static InProcessZkBackend CreateBackend(bool validatorAlwaysSatisfied = true)
    {
        var options = Options.Create(new ZkBackendOptions
        {
            LocalHmacKey = "zk-test-key-012345678901234567890123"
        });

        return new InProcessZkBackend(
            options,
            new FakeHostEnvironment("Development"),
            new FakeWitnessGenerator(),
            new FakeR1csSatisfiabilityValidator(validatorAlwaysSatisfied));
    }

    private static string ComputeLegacyMacBase64(
        string hashPublicBase64,
        string clientId,
        string nonce,
        string circuitId,
        int version)
    {
        var hashPublicBytes = Convert.FromBase64String(hashPublicBase64);
        var metadataBytes = Encoding.UTF8.GetBytes($"{clientId}|{nonce}|{circuitId}|{version}");

        var payload = new byte[hashPublicBytes.Length + metadataBytes.Length];
        Buffer.BlockCopy(hashPublicBytes, 0, payload, 0, hashPublicBytes.Length);
        Buffer.BlockCopy(metadataBytes, 0, payload, hashPublicBytes.Length, metadataBytes.Length);

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("zk-test-key-012345678901234567890123"));
        return Convert.ToBase64String(hmac.ComputeHash(payload));
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

    private sealed class FakeR1csSatisfiabilityValidator(bool alwaysSatisfied) : IR1csSatisfiabilityValidator
    {
        public R1csSatisfiabilityResult Validate(
            IReadOnlyList<R1csBuilder.R1csConstraint> constraints,
            IReadOnlyDictionary<int, BigInteger> witness,
            BigInteger modulus)
        {
            if (alwaysSatisfied)
            {
                return R1csSatisfiabilityResult.Satisfied;
            }

            return R1csSatisfiabilityResult.Unsatisfied(new R1csSatisfiabilityFailure(
                ConstraintIndex: 0,
                MissingWitnessIndex: null,
                Left: BigInteger.Zero,
                Right: BigInteger.Zero,
                Output: BigInteger.Zero,
                Residual: BigInteger.One));
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
