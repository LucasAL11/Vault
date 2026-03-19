using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Microsoft.Extensions.Options;

namespace Infrastructure.Zk.Backends;

/// <summary>
/// In-process proof backend used when no external zk service is available.
/// This is an application-local fallback and not a zero-knowledge prover.
/// </summary>
public sealed class InProcessZkBackend : IZkBackend
{
    private readonly byte[] _hmacKey;

    public InProcessZkBackend(IOptions<ZkBackendOptions> options)
    {
        var key = options.Value.LocalHmacKey;
        if (string.IsNullOrWhiteSpace(key) || key.Length < 16)
        {
            throw new InvalidOperationException("ZkBackend:LocalHmacKey must have at least 16 characters.");
        }

        _hmacKey = Encoding.UTF8.GetBytes(key);
    }

    public Task<ZkProofResult> ProveAsync(PreimageRequest request, CancellationToken cancellationToken)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(request.Secret);
        byte[] publicHash = NormalizeHashInput(request.HashPublic);

        byte[] computedHash = SHA256.HashData(secretBytes);
        if (!CryptographicOperations.FixedTimeEquals(computedHash, publicHash))
        {
            throw new InvalidOperationException("Provided hashPublic does not match SHA-256(secret).");
        }

        byte[] mac = ComputeMac(secretBytes, publicHash);

        var payload = new LocalProofPayload(
            SecretBase64: Convert.ToBase64String(secretBytes),
            HashPublicBase64: Convert.ToBase64String(publicHash),
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

        if (payload is null)
        {
            return Task.FromResult(false);
        }

        try
        {
            byte[] secretBytes = Convert.FromBase64String(payload.SecretBase64);
            byte[] hashFromProof = Convert.FromBase64String(payload.HashPublicBase64);
            byte[] macFromProof = Convert.FromBase64String(payload.MacBase64);

            if (!CryptographicOperations.FixedTimeEquals(hashFromProof, expectedHash))
            {
                return Task.FromResult(false);
            }

            byte[] recomputedHash = SHA256.HashData(secretBytes);
            if (!CryptographicOperations.FixedTimeEquals(recomputedHash, expectedHash))
            {
                return Task.FromResult(false);
            }

            byte[] expectedMac = ComputeMac(secretBytes, expectedHash);
            bool valid = CryptographicOperations.FixedTimeEquals(expectedMac, macFromProof);
            return Task.FromResult(valid);
        }
        catch (FormatException)
        {
            return Task.FromResult(false);
        }
    }

    private byte[] ComputeMac(byte[] secretBytes, byte[] hashPublicBytes)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        var payload = new byte[secretBytes.Length + hashPublicBytes.Length];
        Buffer.BlockCopy(secretBytes, 0, payload, 0, secretBytes.Length);
        Buffer.BlockCopy(hashPublicBytes, 0, payload, secretBytes.Length, hashPublicBytes.Length);
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

    private sealed record LocalProofPayload(
        string SecretBase64,
        string HashPublicBase64,
        string MacBase64);
}
