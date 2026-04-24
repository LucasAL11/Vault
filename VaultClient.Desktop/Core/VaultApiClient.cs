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
    private readonly string _challengeAudience;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public VaultApiClient(HttpClient http, CredentialStore credentials, IConfiguration config)
    {
        _http = http;
        _credentials = credentials;
        _baseUrl = (credentials.Get(AppConfig.BaseUrlKey)
            ?? config["Vault:BaseUrl"]
            ?? "https://localhost:7001").TrimEnd('/');
        _challengeAudience = config["Vault:ChallengeAudience"] ?? "vault.secret.request";
    }

    /// <summary>Atualiza a URL base sem reiniciar o app (usado após Setup).</summary>
    public void Reconfigure(string baseUrl)
        => _baseUrl = baseUrl.TrimEnd('/');

    /// <summary>Verifica se o servidor está acessível. Qualquer resposta HTTP é sucesso.</summary>
    public async Task PingAsync(CancellationToken ct = default)
        => await _http.GetAsync(_baseUrl, ct);

    // ── Auth ─────────────────────────────────────────────────────────────────

    /// <summary>Login local com usuário + senha. Lança InvalidOperationException com detalhe em caso de erro.</summary>
    public Task LoginLocalAsync(string username, string password, CancellationToken ct = default)
        => AuthenticateAsync(new { username, password }, ct);

    /// <summary>Login AD com usuário + domínio + senha. Lança InvalidOperationException com detalhe em caso de erro.</summary>
    public Task LoginAdAsync(string username, string domain, string password, CancellationToken ct = default)
        => AuthenticateAsync(new { username, domain, password }, ct);

    private async Task AuthenticateAsync(object payload, CancellationToken ct)
    {
        var response = await _http.PostAsJsonAsync($"{_baseUrl}/users", payload, ct);

        if (!response.IsSuccessStatusCode)
        {
            // Tenta extrair a mensagem de erro do corpo da resposta (ProblemDetails)
            var body = await response.Content.ReadAsStringAsync(ct);
            var detail = TryExtractDetail(body);
            throw new InvalidOperationException(
                detail ?? $"Falha na autenticação (HTTP {(int)response.StatusCode}).");
        }

        var token = await response.Content.ReadAsStringAsync(ct);
        token = token.Trim('"');

        _credentials.Set("jwt", token);
        SetAuthHeader(token);
    }

    private static string? TryExtractDetail(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // ProblemDetails: { detail, errors: { Field: ["msg"] } }
            if (root.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.String)
                return detail.GetString();

            if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object)
            {
                var msgs = errors.EnumerateObject()
                    .SelectMany(p => p.Value.ValueKind == JsonValueKind.Array
                        ? p.Value.EnumerateArray().Select(v => v.GetString())
                        : [p.Value.GetString()])
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .ToList();
                if (msgs.Count > 0) return string.Join("; ", msgs);
            }
        }
        catch { /* json inválido */ }
        return null;
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

    /// <summary>
    /// Raised when the server returns 401 — token expired or invalidated.
    /// Subscribers (e.g. MainWindow) should navigate the user back to the login screen.
    /// </summary>
    public event EventHandler? SessionExpired;

    private async Task<HttpResponseMessage> SendAsync(Func<Task<HttpResponseMessage>> request)
    {
        var response = await request();
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            Logout();
            SessionExpired?.Invoke(this, EventArgs.Empty);
        }
        return response;
    }

    // ── Secrets ──────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<SecretItem>> ListSecretsAsync(
        Guid vaultId, int page = 1, int pageSize = 50, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.GetAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets?page={page}&pageSize={pageSize}&status=Active&orderBy=name&orderDirection=asc",
            ct));

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

    public async Task<(string Nonce, DateTimeOffset IssuedAt, string Subject)> GetChallengeAsync(
        string clientId, string subject, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.PostAsJsonAsync($"{_baseUrl}/auth/challenge",
            new { clientId, subject, audience = _challengeAudience }, ct));

        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var nonce       = doc.RootElement.GetProperty("nonce").GetString()!;
        var issuedAt    = doc.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        // Use the subject the server normalised and stored in the nonce scope.
        // The server may normalise (FQDN, ToUpperInvariant) differently from what the
        // client sent, so we must echo it back in the proof payload and the request body.
        var serverSubject = doc.RootElement.TryGetProperty("subject", out var subjEl)
            ? (subjEl.GetString() ?? subject)
            : subject;
        return (nonce, issuedAt, serverSubject);
    }

    /// <summary>
    /// Solicita o valor do segredo via prova HMAC-SHA256.
    /// Retorna o valor como bytes UTF-8. O chamador deve zerar o array após uso.
    /// </summary>
    public async Task<byte[]> RequestSecretValueAsync(
        Guid vaultId, string secretName, string clientId, string clientSecret,
        string subject, string reason, string ticket, CancellationToken ct = default)
    {
        var (nonce, issuedAt, serverSubject) = await GetChallengeAsync(clientId, subject, ct);

        var proof = ProofBuilder.Build(
            vaultId, secretName, clientId, serverSubject,
            reason, ticket, nonce, issuedAt, clientSecret);

        var encodedName = Uri.EscapeDataString(secretName);
        var response = await SendAsync(() => _http.PostAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets/request?name={encodedName}",
            new
            {
                contractVersion  = "v1",
                reason,
                ticket,
                clientId,
                subject          = serverSubject,   // echo the server-normalised subject
                nonce,
                issuedAt,
                proof
            }, ct));

        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var value = doc.RootElement.GetProperty("value").GetString()!;
        return Encoding.UTF8.GetBytes(value);
    }

    // ── Admin: AD Maps ────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<AdMapItem>> ListAdMapsAsync(
        Guid vaultId, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.GetAsync(
            $"{_baseUrl}/vaults/{vaultId}/ad-maps?includeInactive=true", ct));
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
        var response = await SendAsync(() => _http.PostAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/ad-maps",
            new { groupId, permission }, ct));
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteAdMapAsync(Guid vaultId, Guid adMapId, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.DeleteAsync(
            $"{_baseUrl}/vaults/{vaultId}/ad-maps/{adMapId}", ct));
        response.EnsureSuccessStatusCode();
    }

    // ── Admin: Secrets Management ───────────────────────────────────────────

    public async Task UpsertSecretAsync(
        Guid vaultId, string name, string value, string? contentType = null,
        CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.PutAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets/{name}",
            new { value, contentType }, ct));
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteSecretAsync(Guid vaultId, string name, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.DeleteAsync(
            $"{_baseUrl}/vaults/{vaultId}/secrets/{name}", ct));
        response.EnsureSuccessStatusCode();
    }

    // ── Admin: Users ────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<UserItem>> ListUsersAsync(CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.GetAsync($"{_baseUrl}/users/list", ct));
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
        var response = await SendAsync(() => _http.PostAsJsonAsync(
            $"{_baseUrl}/users/register",
            new { username, password, firstName, lastName }, ct));
        response.EnsureSuccessStatusCode();
    }

    // ── Admin: Vaults ──────────────────────────────────────────────────────

    public async Task<IReadOnlyList<VaultItem>> ListVaultsAsync(CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.GetAsync($"{_baseUrl}/vaults", ct));
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

    public async Task UpdateVaultAsync(
        Guid vaultId, string name, string description, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.PutAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}",
            new { name, description }, ct));
        response.EnsureSuccessStatusCode();
    }

    public async Task<bool> DeleteVaultAsync(Guid vaultId, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.DeleteAsync(
            $"{_baseUrl}/vaults/{vaultId}", ct));
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("hardDeleted").GetBoolean();
    }

    public async Task<Guid> CreateVaultAsync(
        string name, string slug, string description,
        string tenantId, string group, string environment,
        CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.PostAsJsonAsync($"{_baseUrl}/vaults",
            new { name, slug, description, tenantId, group, environment }, ct));
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    // ── Autofill Rules ────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<AutofillRuleItem>> ListAutofillRulesAsync(
        Guid vaultId, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.GetAsync(
            $"{_baseUrl}/vaults/{vaultId}/autofill-rules", ct));
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var items = doc.RootElement.GetProperty("items");

        return items.EnumerateArray().Select(i => new AutofillRuleItem(
            Id: i.GetProperty("id").GetGuid(),
            VaultId: i.GetProperty("vaultId").GetGuid(),
            UrlPattern: i.GetProperty("urlPattern").GetString()!,
            Login: i.GetProperty("login").GetString()!,
            SecretName: i.GetProperty("secretName").GetString()!,
            IsActive: i.GetProperty("isActive").GetBoolean(),
            CreatedAt: i.GetProperty("createdAt").GetDateTimeOffset()
        )).ToList();
    }

    public async Task<Guid> CreateAutofillRuleAsync(
        Guid vaultId, string urlPattern, string login, string secretName,
        CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.PostAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/autofill-rules",
            new { vaultId, urlPattern, login, secretName, isActive = true }, ct));
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    public async Task UpdateAutofillRuleAsync(
        Guid vaultId, Guid ruleId, string urlPattern, string login, string secretName, bool isActive,
        CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.PutAsJsonAsync(
            $"{_baseUrl}/vaults/{vaultId}/autofill-rules/{ruleId}",
            new { urlPattern, login, secretName, isActive }, ct));
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteAutofillRuleAsync(
        Guid vaultId, Guid ruleId, CancellationToken ct = default)
    {
        var response = await SendAsync(() => _http.DeleteAsync(
            $"{_baseUrl}/vaults/{vaultId}/autofill-rules/{ruleId}", ct));
        response.EnsureSuccessStatusCode();
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// <summary>Retorna o JWT bruto armazenado (para checagem de claims no client).</summary>
    public string? CurrentJwt => _credentials.Get("jwt");

    private void SetAuthHeader(string token)
        => _http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
}
