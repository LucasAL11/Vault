using System.Security.Cryptography;
using System.Text;
using Api.Security;
using Application.Authentication;
using Infrastructure.Security;

namespace Api.Endpoints.Vault.Secret;

internal static class SecretProofHelpers
{
    internal static bool TryGetClientSecret(string clientId, AuthChallengeOptions options, out string secret)
    {
        secret = string.Empty;
        if (!options.ClientSecrets.TryGetValue(clientId, out var configured) || string.IsNullOrWhiteSpace(configured))
            return false;
        secret = configured;
        return true;
    }

    internal static string ResolveFallbackSecret(AuthChallengeOptions options)
    {
        foreach (var entry in options.ClientSecrets)
        {
            if (!string.IsNullOrWhiteSpace(entry.Value))
                return entry.Value;
        }
        return "vault-secret-request-fallback-secret";
    }

    internal static string BuildProofPayload(
        Guid vaultId, string secretName, string clientId, string subject,
        string reason, string ticket, string nonce, DateTimeOffset issuedAtUtc)
        => $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|{subject.Trim().ToUpperInvariant()}|{reason.Trim()}|{NormalizeTicketId(ticket)}|{nonce.Trim()}|{issuedAtUtc:O}";

    internal static string? ResolveTicket(string? ticket, string? ticketId)
    {
        if (!string.IsNullOrWhiteSpace(ticket)) return ticket.Trim();
        if (!string.IsNullOrWhiteSpace(ticketId)) return ticketId.Trim();
        return null;
    }

    internal static string NormalizeTicketId(string? ticket)
        => string.IsNullOrWhiteSpace(ticket) ? "-" : ticket.Trim();

    internal static bool IsSignatureValid(string payload, string signatureBase64Url, string clientSecret)
    {
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        using var hmac = new HMACSHA256(secretBytes);
        var expected = hmac.ComputeHash(payloadBytes);
        var parsed = TryFromBase64Url(signatureBase64Url, out var provided);
        return parsed & FixedTimeEquals(provided, expected);
    }

    internal static bool IsSignatureValid(string payload, byte[] providedSignature, bool signatureParsed, string clientSecret)
    {
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        using var hmac = new HMACSHA256(secretBytes);
        var expected = hmac.ComputeHash(payloadBytes);
        return signatureParsed & FixedTimeEquals(providedSignature, expected);
    }

    internal static bool IsWithinSkewWindow(
        DateTimeOffset issuedAtUtc, AuthChallengeOptions challengeOptions, NonceStoreOptions nonceStoreOptions)
    {
        var skew = Math.Max(0, challengeOptions.ClockSkewSeconds);
        var ttl = Math.Max(1, nonceStoreOptions.TtlSeconds);
        var now = DateTimeOffset.UtcNow;
        return now >= issuedAtUtc.AddSeconds(-skew) && now <= issuedAtUtc.AddSeconds(ttl + skew);
    }

    internal static bool TryFromBase64Url(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        var normalized = input.Replace('-', '+').Replace('_', '/');
        normalized = (normalized.Length % 4) switch
        {
            2 => normalized + "==",
            3 => normalized + "=",
            1 => null!,
            _ => normalized
        };
        if (normalized is null) return false;

        try { bytes = Convert.FromBase64String(normalized); return bytes.Length > 0; }
        catch (FormatException) { return false; }
    }

    private static bool FixedTimeEquals(ReadOnlySpan<byte> provided, ReadOnlySpan<byte> expected)
    {
        var len = expected.Length;
        Span<byte> a = stackalloc byte[len];
        Span<byte> b = stackalloc byte[len];
        a.Clear(); b.Clear();
        provided[..Math.Min(provided.Length, len)].CopyTo(a);
        expected[..Math.Min(expected.Length, len)].CopyTo(b);
        return CryptographicOperations.FixedTimeEquals(a, b)
             & (provided.Length == len)
             & (expected.Length == len);
    }
}
