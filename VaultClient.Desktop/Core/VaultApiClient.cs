using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using VaultClient.Desktop.Models;

namespace VaultClient.Desktop.Core;

public sealed class VaultApiClient
{
    private readonly HttpClient _http;
    private readonly CredentialStore _credentials;
    private string _baseUrl;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public VaultApiClient(HttpClient http, CredentialStore credentials, IConfiguration config)
    {
        _http = http;
        _credentials = credentials;
        _baseUrl = (credentials.Get(AppConfig.BaseUrlKey)
            ?? config["Vault:BaseUrl"]
            ?? "https://localhost:7001").TrimEnd('/');
    }

    /// <summary>Atualiza a URL base sem reiniciar o app (usado após Setup).</summary>
    public void Reconfigure(string baseUrl)
        => _baseUrl = baseUrl.TrimEnd('/');

    /// <summary>Verifica se o servidor está acessível. Qualquer resposta HTTP é sucesso.</summary>
    public async Task PingAsync(CancellationToken ct = default)
        => await _http.GetAsync(_baseUrl, ct);

    // ── Auth ─────────────────────────────────────────────────────────────────

    public async Task<bool> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"{_baseUrl}/users",
            new { username, password }, ct);

        if (!response.IsSuccessStatusCode)
            return false;

        var token = await response.Content.ReadAsStringAsync(ct);
        token = token.Trim('"');

        _credentials.Set("jwt", token);
        SetAuthHeader(token);
        return true;
    }

    public void RestoreSession()
    {
        var token = _credentials.Get("jwt");
        if (!string.IsNullOrWhiteSpace(token))
            SetAuthHeader(token);
    }

    public void Logout()
    {
        _credentials.Remove("jwt");
        _http.DefaultRequestHeaders.Authorization = null;
    }

    public bool HasSession => _credentials.Get("jwt") is not null;

    // ── Secrets ──────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<SecretItem>> ListSecretsAsync(
        Guid vaultId, int page = 1, int pageSize = 50, CancellationToken ct = default)
    {
        var response = await _http.GetAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets?page={page}&pageSize={pageSize}&status=Active&orderBy=name&orderDirection=asc",
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
        var response = await _http.PostAsJsonAsync($"{_baseUrl}/auth/challenge",
            new { clientId, subject, audience = "VaultSecretRequest" }, ct);

        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var nonce = doc.RootElement.GetProperty("nonce").GetString()!;
        var issuedAt = doc.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        return (nonce, issuedAt);
    }

    /// <summary>
    /// Solicita o valor do segredo via prova HMAC-SHA256.
    /// Retorna o valor como bytes UTF-8. O chamador deve zerar o array após uso.
    /// </summary>
    public async Task<byte[]> RequestSecretValueAsync(
        Guid vaultId, string secretName, string clientId, string clientSecret,
        string subject, string reason, string ticket, CancellationToken ct = default)
    {
        var (nonce, issuedAt) = await GetChallengeAsync(clientId, subject, ct);

        var proof = ProofBuilder.Build(
            vaultId, secretName, clientId, subject,
            reason, ticket, nonce, issuedAt, clientSecret);

        var response = await _http.PostAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets/{secretName}/request",
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
        return Encoding.UTF8.GetBytes(value);
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private void SetAuthHeader(string token)
        => _http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
}
