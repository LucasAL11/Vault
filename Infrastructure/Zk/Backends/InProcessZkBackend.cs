using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Linq;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Infrastructure.Zk.Backends;

/// <summary>
/// In-process proof backend used when no external zk service is available.
/// This is an application-local fallback and not a zero-knowledge prover.
/// </summary>
public sealed class InProcessZkBackend : IZkBackend
{
    private const int CurrentProofSchemaVersion = 1;
    private readonly byte[] _hmacKey;
    private readonly IZkWitnessGenerator _witnessGenerator;

    public InProcessZkBackend(
        IOptions<ZkBackendOptions> options,
        IHostEnvironment hostEnvironment,
        IZkWitnessGenerator witnessGenerator)
    {
        _witnessGenerator = witnessGenerator;

        var key = options.Value.LocalHmacKey;
        if (string.IsNullOrWhiteSpace(key) || key.Length < 16)
        {
            throw new InvalidOperationException("ZkBackend:LocalHmacKey must have at least 16 characters.");
        }

        if (hostEnvironment.IsProduction() && !IsStrongKey(key))
        {
            throw new InvalidOperationException(
                "ZkBackend:LocalHmacKey is weak for Production. Use at least 32 bytes of entropy (base64 or strong secret).");
        }

        _hmacKey = Encoding.UTF8.GetBytes(key);
    }

    public Task<ZkProofResult> ProveAsync(PreimageRequest request, CancellationToken cancellationToken)
    {
        var witness = _witnessGenerator.Generate(request);

        byte[] secretHash = Convert.FromBase64String(witness.SecretSha256Base64);
        byte[] publicHash = Convert.FromBase64String(witness.HashPublicBase64);

        if (!CryptographicOperations.FixedTimeEquals(secretHash, publicHash))
        {
            throw new InvalidOperationException("Provided hashPublic does not match SHA-256(secret).");
        }

        byte[] mac = ComputeMac(
            publicHash,
            witness.ClientId,
            witness.Nonce,
            witness.CircuitId,
            witness.Version);

        var payload = new LocalProofPayload(
            SchemaVersion: CurrentProofSchemaVersion,
            Witness: new LocalProofWitness(
                HashPublicBase64: witness.HashPublicBase64,
                ClientId: witness.ClientId,
                Nonce: witness.Nonce,
                CircuitId: witness.CircuitId,
                Version: witness.Version),
            MacBase64: Convert.ToBase64String(mac));

        byte[] proofBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        return Task.FromResult(new ZkProofResult(Proof: proofBytes, PublicInputs: publicHash));
    }

    public Task<bool> VerifyAsync(VerificationRequest request, CancellationToken cancellationToken)
    {
        byte[] expectedHash = NormalizeHashInput(request.HashPublic);

        byte[] proofBytes;
        try
        {
            proofBytes = Convert.FromBase64String(request.Proof);
        }
        catch (FormatException)
        {
            return Task.FromResult(false);
        }

        LocalProofPayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<LocalProofPayload>(proofBytes);
        }
        catch (JsonException)
        {
            return Task.FromResult(false);
        }

        if (payload?.Witness is null)
        {
            return Task.FromResult(false);
        }

        if (payload.SchemaVersion != CurrentProofSchemaVersion)
        {
            return Task.FromResult(false);
        }

        try
        {
            var witness = payload.Witness;
            byte[] hashFromProof = Convert.FromBase64String(witness.HashPublicBase64);
            byte[] macFromProof = Convert.FromBase64String(payload.MacBase64);

            if (!string.Equals(witness.ClientId, request.ClientId, StringComparison.Ordinal))
            {
                return Task.FromResult(false);
            }

            if (!string.Equals(witness.Nonce, request.Nonce, StringComparison.Ordinal))
            {
                return Task.FromResult(false);
            }

            if (!CryptographicOperations.FixedTimeEquals(hashFromProof, expectedHash))
            {
                return Task.FromResult(false);
            }

            if (string.IsNullOrWhiteSpace(witness.CircuitId) || witness.Version <= 0)
            {
                return Task.FromResult(false);
            }

            byte[] expectedMac = ComputeMac(
                expectedHash,
                witness.ClientId,
                witness.Nonce,
                witness.CircuitId,
                witness.Version);
            bool valid = CryptographicOperations.FixedTimeEquals(expectedMac, macFromProof);
            return Task.FromResult(valid);
        }
        catch (FormatException)
        {
            return Task.FromResult(false);
        }
    }

    private byte[] ComputeMac(
        byte[] hashPublicBytes,
        string clientId,
        string nonce,
        string circuitId,
        int version)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        var meta = Encoding.UTF8.GetBytes($"{clientId}|{nonce}|{circuitId}|{version}");
        var payload = new byte[hashPublicBytes.Length + meta.Length];
        Buffer.BlockCopy(hashPublicBytes, 0, payload, 0, hashPublicBytes.Length);
        Buffer.BlockCopy(meta, 0, payload, hashPublicBytes.Length, meta.Length);
        return hmac.ComputeHash(payload);
    }

    private static byte[] NormalizeHashInput(string hashPublic)
    {
        if (LooksLikeHex(hashPublic) && TryParseHex(hashPublic, out var hexBytes))
        {
            return hexBytes;
        }

        if (TryParseBase64(hashPublic, out var bytes))
        {
            return bytes;
        }

        if (TryParseHex(hashPublic, out bytes))
        {
            return bytes;
        }

        throw new InvalidOperationException("hashPublic must be base64 or hex-encoded SHA-256.");
    }

    private static bool TryParseBase64(string input, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(input);
            return bytes.Length == 32;
        }
        catch
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static bool TryParseHex(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (input.Length % 2 != 0)
        {
            return false;
        }

        var buffer = new byte[input.Length / 2];
        for (int i = 0; i < buffer.Length; i++)
        {
            int hi = HexValue(input[2 * i]);
            int lo = HexValue(input[2 * i + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }

            buffer[i] = (byte)((hi << 4) | lo);
        }

        bytes = buffer;
        return bytes.Length > 0;
    }

    private static int HexValue(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static bool LooksLikeHex(string input)
    {
        if (string.IsNullOrWhiteSpace(input) || input.Length % 2 != 0)
        {
            return false;
        }

        for (int i = 0; i < input.Length; i++)
        {
            if (HexValue(input[i]) < 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsStrongKey(string key)
    {
        const string defaultDevKey = "dev-local-zk-key-change-me";
        if (string.Equals(key, defaultDevKey, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var decoded = Convert.FromBase64String(key);
            if (decoded.Length >= 32)
            {
                return true;
            }
        }
        catch
        {
            // not base64, fallback to plain-text heuristics
        }

        if (Encoding.UTF8.GetByteCount(key) < 32)
        {
            return false;
        }

        int classes = 0;
        if (key.Any(char.IsLower)) classes++;
        if (key.Any(char.IsUpper)) classes++;
        if (key.Any(char.IsDigit)) classes++;
        if (key.Any(c => !char.IsLetterOrDigit(c))) classes++;
        return classes >= 3;
    }

    private sealed record LocalProofPayload(
        int SchemaVersion,
        LocalProofWitness Witness,
        string MacBase64);

    private sealed record LocalProofWitness(
        string HashPublicBase64,
        string ClientId,
        string Nonce,
        string CircuitId,
        int Version);
}
