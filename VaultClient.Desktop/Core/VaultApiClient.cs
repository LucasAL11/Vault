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

    /// <summary>Login local com usuário + senha.</summary>
    public Task<bool> LoginLocalAsync(string username, string password, CancellationToken ct = default)
        => AuthenticateAsync(new { username, password }, ct);

    /// <summary>Login AD com usuário + domínio + senha (validada contra o AD).</summary>
    public Task<bool> LoginAdAsync(string username, string domain, string password, CancellationToken ct = default)
        => AuthenticateAsync(new { username, domain, password }, ct);

    private async Task<bool> AuthenticateAsync(object payload, CancellationToken ct)
    {
        var response = await _http.PostAsJsonAsync($"{_baseUrl}/users", payload, ct);

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

    // ── Admin: AD Maps ────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<AdMapItem>> ListAdMapsAsync(
        Guid vaultId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync(
            $"{_baseUrl}/vaults/{vaultId}/ad-maps?includeInactive=true", ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var items = doc.RootElement.GetProperty("items");

        return items.EnumerateArray().Select(i => new AdMapItem(
            Id: i.GetProperty("id").GetGuid(),
            GroupId: i.GetProperty("groupId").GetString()!,
            Permission: i.GetProperty("permission").ToString(),
            IsActive: i.GetProperty("isActive").GetBoolean()
        )).ToList();
    }

    public async Task CreateAdMapAsync(
        Guid vaultId, string groupId, string permission, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/ad-maps",
            new { groupId, permission }, ct);
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteAdMapAsync(Guid vaultId, Guid adMapId, CancellationToken ct = default)
    {
        var response = await _http.DeleteAsync(
            $"{_baseUrl}/vaults/{vaultId}/ad-maps/{adMapId}", ct);
        response.EnsureSuccessStatusCode();
    }

    // ── Admin: Secrets Management ───────────────────────────────────────────

    public async Task UpsertSecretAsync(
        Guid vaultId, string name, string value, string? contentType = null,
        CancellationToken ct = default)
    {
        var response = await _http.PutAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets/{name}",
            new { value, contentType }, ct);
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteSecretAsync(Guid vaultId, string name, CancellationToken ct = default)
    {
        var response = await _http.DeleteAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets/{name}", ct);
        response.EnsureSuccessStatusCode();
    }

    // ── Admin: Users ────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<UserItem>> ListUsersAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"{_baseUrl}/users/list", ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.EnumerateArray().Select(u => new UserItem(
            Id: u.GetProperty("id").GetGuid(),
            Username: u.GetProperty("userName").GetString()!,
            FirstName: u.TryGetProperty("firstName", out var fn) ? fn.GetString() ?? "" : "",
            LastName: u.TryGetProperty("lastName", out var ln) ? ln.GetString() ?? "" : ""
        )).ToList();
    }

    public async Task RegisterUserAsync(
        string username, string password, string firstName, string lastName,
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            $"{_baseUrl}/users/register",
            new { username, password, firstName, lastName }, ct);
        response.EnsureSuccessStatusCode();
    }

    // ── Admin: Vaults ──────────────────────────────────────────────────────

    public async Task<IReadOnlyList<VaultItem>> ListVaultsAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"{_baseUrl}/vaults", ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.EnumerateArray().Select(v => new VaultItem(
            Id: v.GetProperty("id").GetGuid(),
            Name: v.GetProperty("name").GetString()!,
            Slug: v.GetProperty("slug").GetString()!,
            Description: v.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "",
            TenantId: v.TryGetProperty("tenantId", out var t) ? t.GetString() ?? "" : "",
            Group: v.TryGetProperty("group", out var g) ? g.GetString() ?? "" : "",
            Environment: v.TryGetProperty("environment", out var e) ? e.GetString() ?? "" : ""
        )).ToList();
    }

    public async Task<Guid> CreateVaultAsync(
        string name, string slug, string description,
        string tenantId, string group, string environment,
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"{_baseUrl}/vaults",
            new { name, slug, description, tenantId, group, environment }, ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// <summary>Retorna o JWT bruto armazenado (para checagem de claims no client).</summary>
    public string? CurrentJwt => _credentials.Get("jwt");

    private void SetAuthHeader(string token)
        => _http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
}
