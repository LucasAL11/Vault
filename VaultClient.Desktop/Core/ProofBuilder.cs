using System.Security.Cryptography;
using System.Text;

namespace VaultClient.Desktop.Core;

public static class ProofBuilder
{
    public static string Build(
        Guid vaultId,
        string secretName,
        string clientId,
        string subject,
        string reason,
        string ticket,
        string nonce,
        DateTimeOffset issuedAt,
        string clientSecret)
    {
        var normalizedTicket = string.IsNullOrWhiteSpace(ticket) ? "-" : ticket.Trim();
        var payload = $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|{subject.Trim().ToUpperInvariant()}|{reason.Trim()}|{normalizedTicket}|{nonce.Trim()}|{issuedAt:O}";

        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);

        using var hmac = new HMACSHA256(secretBytes);
        var hash = hmac.ComputeHash(payloadBytes);

        CryptographicOperations.ZeroMemory(secretBytes);

        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
