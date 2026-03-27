using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using VaultClient.Desktop.Models;

namespace VaultClient.Desktop.Core;

public sealed class VaultApiClient(HttpClient http, CredentialStore credentials)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // ── Auth ─────────────────────────────────────────────────────────────────

    /// <summary>Autentica com login local e persiste o JWT.</summary>
    public async Task<bool> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        var response = await http.PostAsJsonAsync("/users",
            new { username, password }, ct);

        if (!response.IsSuccessStatusCode)
            return false;

        var token = await response.Content.ReadAsStringAsync(ct);
        token = token.Trim('"');

        credentials.Set("jwt", token);
        SetAuthHeader(token);
        return true;
    }

    public void RestoreSession()
    {
        var token = credentials.Get("jwt");
        if (!string.IsNullOrWhiteSpace(token))
            SetAuthHeader(token);
    }

    public void Logout()
    {
        credentials.Remove("jwt");
        http.DefaultRequestHeaders.Authorization = null;
    }

    public bool HasSession => credentials.Get("jwt") is not null;

    // ── Secrets ──────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<SecretItem>> ListSecretsAsync(
        Guid vaultId, int page = 1, int pageSize = 50, CancellationToken ct = default)
    {
        var response = await http.GetAsync(
            $"/vaults/{vaultId}/secrets?page={page}&pageSize={pageSize}&status=Active&orderBy=name&orderDirection=asc",
            ct);

        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var items = doc.RootElement.GetProperty("items");

        return items.EnumerateArray().Select(i => new SecretItem(
            Name: i.GetProperty("name").GetString()!,
            CurrentVersion: i.GetProperty("currentVersion").GetInt32(),
            ContentType: i.TryGetProperty("contentType", out var ct2) ? ct2.GetString() : null,
            KeyReference: i.TryGetProperty("keyReference", out var kr) ? kr.GetString() : null,
            IsRevoked: i.TryGetProperty("isRevoked", out var ir) ? ir.GetBoolean() : null,
            Expires: i.TryGetProperty("expires", out var exp) && exp.ValueKind != JsonValueKind.Null
                ? exp.GetDateTimeOffset()
                : null
        )).ToList();
    }

    // ── Secret Value via Proof ────────────────────────────────────────────────

    public async Task<(string Nonce, DateTimeOffset IssuedAt)> GetChallengeAsync(
        string clientId, string subject, CancellationToken ct = default)
    {
        var response = await http.PostAsJsonAsync("/auth/challenge",
            new { clientId, subject, audience = "VaultSecretRequest" }, ct);

        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var nonce = doc.RootElement.GetProperty("nonce").GetString()!;
        var issuedAt = doc.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        return (nonce, issuedAt);
    }

    /// <summary>
    /// Solicita o valor do segredo via prova HMAC-SHA256.
    /// Retorna o valor como bytes UTF-8 — o chamador é responsável por
    /// zerar o array após uso via CryptographicOperations.ZeroMemory.
    /// </summary>
    public async Task<byte[]> RequestSecretValueAsync(
        Guid vaultId, string secretName, string clientId, string clientSecret,
        string subject, string reason, string ticket, CancellationToken ct = default)
    {
        var (nonce, issuedAt) = await GetChallengeAsync(clientId, subject, ct);

        var proof = ProofBuilder.Build(
            vaultId, secretName, clientId, subject,
            reason, ticket, nonce, issuedAt, clientSecret);

        var response = await http.PostAsJsonAsync(
            $"/vaults/{vaultId}/secrets/{secretName}/request",
            new
            {
                contractVersion = "v1",
                reason,
                ticket,
                clientId,
                nonce,
                issuedAt,
                proof
            }, ct);

        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var value = doc.RootElement.GetProperty("value").GetString()!;

        var bytes = Encoding.UTF8.GetBytes(value);
        return bytes;
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private void SetAuthHeader(string token)
        => http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
}
