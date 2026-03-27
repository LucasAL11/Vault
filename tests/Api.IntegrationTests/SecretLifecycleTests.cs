using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Api.Endpoints.Users;
using Api.IntegrationTests.Infrastructure;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Api.IntegrationTests;

/// <summary>
/// Teste de ciclo de vida completo de um segredo:
/// criar → ler metadados → listar versões → solicitar valor com prova →
/// rotacionar → revogar versão antiga → solicitar valor atual → listar → auditar.
/// </summary>
public class SecretLifecycleTests : IClassFixture<ApiTestFactory>
{
    private const string SecretName = "LIFECYCLE_SECRET";
    private const string ValueV1 = "senha-lifecycle-v1";
    private const string ValueV2 = "senha-lifecycle-v2";
    private const string ClientId = "local-dev-client";
    private const string ClientSecret = "dev-shared-secret-please-rotate";
    private const string Subject = "PLT\\integration.user";
    private const string ContractVersion = "v1";

    private readonly ApiTestFactory _factory;

    public SecretLifecycleTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task SecretLifecycle_EndToEnd_ShouldCreateRotateRevokeAndAudit()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        // ── 1. CRIAR (v1) ────────────────────────────────────────────────────────
        var putV1 = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}",
            new { value = ValueV1, contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });

        Assert.Equal(HttpStatusCode.OK, putV1.StatusCode);

        using var putV1Json = JsonDocument.Parse(await putV1.Content.ReadAsStringAsync());
        Assert.Equal(1, putV1Json.RootElement.GetProperty("version").GetInt32());
        Assert.False(putV1Json.RootElement.TryGetProperty("value", out _),
            "A resposta do PUT não deve expor o valor em claro.");

        // Verificar no banco: valor está encriptado e auditado
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var secret = await db.Secrets.SingleAsync(x =>
                x.VaultId == ApiTestFactory.VaultId && x.Name == SecretName);

            var version = await db.SecretVersions
                .Where(x => x.SecretId == secret.Id && x.Version == 1)
                .SingleAsync();

            Assert.NotEmpty(version.CipherText);
            Assert.NotEmpty(version.Nonce);
            Assert.False(version.CipherText.SequenceEqual(Encoding.UTF8.GetBytes(ValueV1)),
                "O valor não deve estar em claro no banco.");

            Assert.True(
                await db.SecretAuditEntries.AnyAsync(x =>
                    x.VaultId == ApiTestFactory.VaultId &&
                    x.SecretName == SecretName &&
                    x.Action == "SECRET_WRITE"),
                "Deve existir audit entry SECRET_WRITE após criação.");
        }

        // ── 2. LER METADADOS ─────────────────────────────────────────────────────
        var metaResponse = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}");

        Assert.Equal(HttpStatusCode.OK, metaResponse.StatusCode);
        Assert.True(metaResponse.Headers.CacheControl?.NoStore ?? false,
            "Cache-Control: no-store obrigatório em endpoints de segredo.");

        using var metaJson = JsonDocument.Parse(await metaResponse.Content.ReadAsStringAsync());
        Assert.Equal(SecretName, metaJson.RootElement.GetProperty("name").GetString());
        Assert.Equal(1, metaJson.RootElement.GetProperty("version").GetInt32());
        Assert.False(metaJson.RootElement.TryGetProperty("value", out _),
            "Endpoint de metadados não deve expor o valor.");
        Assert.True(metaJson.RootElement.TryGetProperty("keyReference", out _));

        // ── 3. LISTAR VERSÕES (somente v1) ───────────────────────────────────────
        var versionsV1Response = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}/versions?includeRevoked=false");

        Assert.Equal(HttpStatusCode.OK, versionsV1Response.StatusCode);
        Assert.True(versionsV1Response.Headers.CacheControl?.NoStore ?? false);

        using var versionsV1Json = JsonDocument.Parse(await versionsV1Response.Content.ReadAsStringAsync());
        var versionsV1Array = versionsV1Json.RootElement.GetProperty("versions");
        Assert.Equal(1, versionsV1Array.GetArrayLength());
        Assert.Equal(1, versionsV1Array[0].GetProperty("version").GetInt32());
        Assert.False(versionsV1Array[0].TryGetProperty("value", out _),
            "Endpoint de versões não deve expor o valor.");

        // ── 4. SOLICITAR VALOR COM PROVA CRIPTOGRÁFICA (v1) ──────────────────────
        var (nonceV1, issuedAtV1) = await IssueChallengeAsync(client);
        var proofV1 = BuildProof(
            ApiTestFactory.VaultId, SecretName, ClientId, Subject,
            "Teste ciclo de vida v1", "INC-LIFECYCLE-01",
            nonceV1, issuedAtV1, ClientSecret);

        var requestV1 = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}/request",
            new
            {
                contractVersion = ContractVersion,
                reason = "Teste ciclo de vida v1",
                ticket = "INC-LIFECYCLE-01",
                clientId = ClientId,
                nonce = nonceV1,
                issuedAt = issuedAtV1,
                proof = proofV1
            });

        Assert.Equal(HttpStatusCode.OK, requestV1.StatusCode);
        Assert.True(requestV1.Headers.CacheControl?.NoStore ?? false);

        using var requestV1Json = JsonDocument.Parse(await requestV1.Content.ReadAsStringAsync());
        Assert.Equal(ValueV1, requestV1Json.RootElement.GetProperty("value").GetString());
        Assert.Equal(SecretName, requestV1Json.RootElement.GetProperty("name").GetString());

        // ── 5. ROTACIONAR (v2) ───────────────────────────────────────────────────
        var putV2 = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}",
            new { value = ValueV2, contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });

        Assert.Equal(HttpStatusCode.OK, putV2.StatusCode);

        using var putV2Json = JsonDocument.Parse(await putV2.Content.ReadAsStringAsync());
        Assert.Equal(2, putV2Json.RootElement.GetProperty("version").GetInt32());

        // ── 6. LISTAR VERSÕES (v1 e v2) ──────────────────────────────────────────
        var versionsV2Response = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}/versions?includeRevoked=true");

        Assert.Equal(HttpStatusCode.OK, versionsV2Response.StatusCode);

        using var versionsV2Json = JsonDocument.Parse(await versionsV2Response.Content.ReadAsStringAsync());
        var versionsV2Array = versionsV2Json.RootElement.GetProperty("versions");
        Assert.Equal(2, versionsV2Array.GetArrayLength());
        Assert.Equal(2, versionsV2Json.RootElement.GetProperty("currentVersion").GetInt32());

        // ── 7. REVOGAR v1 ────────────────────────────────────────────────────────
        var revokeResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}/versions/1/revoke",
            new { reason = "Rotação de segurança — ciclo de vida" });

        Assert.Equal(HttpStatusCode.OK, revokeResponse.StatusCode);

        using var revokeJson = JsonDocument.Parse(await revokeResponse.Content.ReadAsStringAsync());
        Assert.Equal(SecretName, revokeJson.RootElement.GetProperty("name").GetString());
        Assert.Equal(1, revokeJson.RootElement.GetProperty("version").GetInt32());
        Assert.True(revokeJson.RootElement.GetProperty("isRevoked").GetBoolean());
        Assert.False(revokeJson.RootElement.GetProperty("alreadyRevoked").GetBoolean());

        // Verificar no banco que a versão está marcada como revogada
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var secret = await db.Secrets.SingleAsync(x =>
                x.VaultId == ApiTestFactory.VaultId && x.Name == SecretName);
            var v1 = await db.SecretVersions
                .SingleAsync(x => x.SecretId == secret.Id && x.Version == 1);
            Assert.True(v1.IsRevoked);
        }

        // ── 8. SOLICITAR VALOR ATUAL COM PROVA (deve retornar v2) ────────────────
        var (nonceV2, issuedAtV2) = await IssueChallengeAsync(client);
        var proofV2 = BuildProof(
            ApiTestFactory.VaultId, SecretName, ClientId, Subject,
            "Teste ciclo de vida v2", "INC-LIFECYCLE-02",
            nonceV2, issuedAtV2, ClientSecret);

        var requestV2 = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}/request",
            new
            {
                contractVersion = ContractVersion,
                reason = "Teste ciclo de vida v2",
                ticket = "INC-LIFECYCLE-02",
                clientId = ClientId,
                nonce = nonceV2,
                issuedAt = issuedAtV2,
                proof = proofV2
            });

        Assert.Equal(HttpStatusCode.OK, requestV2.StatusCode);

        using var requestV2Json = JsonDocument.Parse(await requestV2.Content.ReadAsStringAsync());
        Assert.True(
            requestV2Json.RootElement.GetProperty("value").GetString() == ValueV2,
            "Após rotação, o valor retornado deve ser o da versão atual (v2).");
        Assert.Equal(2, requestV2Json.RootElement.GetProperty("version").GetInt32());

        // ── 9. LISTAR SEGREDOS (paginação e filtro) ───────────────────────────────
        var listResponse = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets?name={SecretName}&status=Active&page=1&pageSize=10&orderBy=name&orderDirection=asc");

        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        Assert.True(listResponse.Headers.CacheControl?.NoStore ?? false);

        using var listJson = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        var items = listJson.RootElement.GetProperty("items");
        Assert.True(items.GetArrayLength() >= 1);

        var lifecycleItem = items.EnumerateArray()
            .SingleOrDefault(x => x.GetProperty("name").GetString() == SecretName);
        Assert.True(lifecycleItem.ValueKind != JsonValueKind.Undefined,
            $"Segredo '{SecretName}' deve aparecer na listagem.");
        Assert.False(lifecycleItem.TryGetProperty("value", out _),
            "Listagem não deve expor o valor do segredo.");

        // ── 10. AUDITAR — verificar trilha completa ───────────────────────────────
        var auditResponse = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/{SecretName}/audit?take=50");

        Assert.Equal(HttpStatusCode.OK, auditResponse.StatusCode);
        Assert.True(auditResponse.Headers.CacheControl?.NoStore ?? false);

        using var auditJson = JsonDocument.Parse(await auditResponse.Content.ReadAsStringAsync());
        var entries = auditJson.RootElement.GetProperty("entries").EnumerateArray()
            .Select(e => e.GetProperty("action").GetString())
            .ToList();

        Assert.True(entries.Count(a => a == "SECRET_WRITE") == 2,
            "Deve haver 2 entradas SECRET_WRITE (v1 e v2).");
        Assert.True(entries.Count(a => a == "SECRET_REQUEST_VALUE") == 2,
            "Deve haver 2 entradas SECRET_REQUEST_VALUE (uma por prova).");
        Assert.True(entries.Count(a => a == "SECRET_VERSION_REVOKE") == 1,
            "Deve haver 1 entrada SECRET_VERSION_REVOKE.");
        Assert.Contains("SECRET_READ_METADATA", entries);
        Assert.Contains("SECRET_READ_VERSIONS_METADATA", entries);

        // Verificar detalhes do audit de revogação
        using var scope2 = _factory.Services.CreateScope();
        var db2 = scope2.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var revokeAudit = await db2.SecretAuditEntries
            .Where(x =>
                x.VaultId == ApiTestFactory.VaultId &&
                x.SecretName == SecretName &&
                x.Action == "SECRET_VERSION_REVOKE")
            .SingleAsync();

        Assert.True(
            revokeAudit.Details?.Contains("version=1", StringComparison.OrdinalIgnoreCase) == true,
            "Audit de revogação deve conter 'version=1' nos detalhes.");
        Assert.False(string.IsNullOrWhiteSpace(revokeAudit.Actor));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private static async Task<(string Nonce, DateTimeOffset IssuedAtUtc)> IssueChallengeAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = ClientId,
            subject = Subject,
            audience = NonceChallengeAudiences.VaultSecretRequest
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var nonce = json.RootElement.GetProperty("nonce").GetString();
        var issuedAt = json.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();

        Assert.False(string.IsNullOrWhiteSpace(nonce));
        return (nonce!, issuedAt);
    }

    private static string BuildProof(
        Guid vaultId, string secretName, string clientId, string subject,
        string reason, string ticket, string nonce, DateTimeOffset issuedAt, string clientSecret)
    {
        var normalizedTicket = string.IsNullOrWhiteSpace(ticket) ? "-" : ticket.Trim();
        var payload = $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|{subject.Trim().ToUpperInvariant()}|{reason.Trim()}|{normalizedTicket}|{nonce.Trim()}|{issuedAt:O}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(clientSecret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));

        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
