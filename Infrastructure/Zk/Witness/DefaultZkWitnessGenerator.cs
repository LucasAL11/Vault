using System.Security.Cryptography;
using System.Text;
using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;

namespace Infrastructure.Zk.Witness;

internal sealed class DefaultZkWitnessGenerator : IZkWitnessGenerator
{
    private const string CircuitId = "sha256-preimage-v1";
    private const int WitnessVersion = 1;

    public ZkWitness Generate(PreimageRequest request)
    {
        if (request is null)
        {
            throw new InvalidOperationException("Request is required.");
        }

        var secretBytes = Encoding.UTF8.GetBytes(request.Secret);
        var publicHashBytes = NormalizeHashInput(request.HashPublic);
        var secretHash = SHA256.HashData(secretBytes);

        return new ZkWitness(
            SecretBase64: Convert.ToBase64String(secretBytes),
            HashPublicBase64: Convert.ToBase64String(publicHashBytes),
            SecretSha256Base64: Convert.ToBase64String(secretHash),
            ClientId: request.ClientId,
            Nonce: request.Nonce,
            CircuitId: CircuitId,
            Version: WitnessVersion);
    }

    private static byte[] NormalizeHashInput(string hashPublic)
    {
        if (LooksLikeHex(hashPublic) && TryParseHex(hashPublic, out var hexBytes))
        {
            return hexBytes;
        }

        if (TryParseBase64(hashPublic, out var base64Bytes))
        {
            return base64Bytes;
        }

        if (TryParseHex(hashPublic, out var bytes))
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
}
