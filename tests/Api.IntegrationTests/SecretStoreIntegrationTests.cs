using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Api.Endpoints.Users;
using Api.IntegrationTests.Infrastructure;
using Application.Abstractions.Security;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Api.IntegrationTests;

public class SecretStoreIntegrationTests : IClassFixture<ApiTestFactory>
{
    private const string VaultRequestContractVersion = "v1";
    private const string VaultRequestClientId = "local-dev-client";
    private const string VaultRequestClientSecret = "dev-shared-secret-please-rotate";
    private const string AuthenticatedSubject = "PLT\\integration.user";

    private readonly ApiTestFactory _factory;

    public SecretStoreIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task PutSecret_ShouldPersistEncryptedVersion_AndAuditEntry()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var response = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/DB_PASSWORD",
            new
            {
                value = "Senha@SuperSecreta!",
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var secret = await db.Secrets.SingleAsync(x => x.VaultId == ApiTestFactory.VaultId && x.Name == "DB_PASSWORD");
        var version = await db.SecretVersions
            .Where(x => x.SecretId == secret.Id)
            .OrderByDescending(x => x.Version)
            .FirstAsync();

        Assert.NotEmpty(version.CipherText);
        Assert.NotEmpty(version.Nonce);
        Assert.False(version.CipherText.SequenceEqual(Encoding.UTF8.GetBytes("Senha@SuperSecreta!")));
        Assert.False(string.IsNullOrWhiteSpace(version.KeyReference));

        var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();
        var protectedSecret = new ProtectedSecret(version.CipherText, version.Nonce, version.KeyReference);
        var correctContext = new SecretProtectionContext(ApiTestFactory.VaultId, secret.Id, version.Version);
        var wrongContext = correctContext with { Version = version.Version + 1 };

        var plaintext = await protector.UnprotectAsync(protectedSecret, correctContext);
        Assert.Equal("Senha@SuperSecreta!", plaintext);

        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(protectedSecret, wrongContext));

        var hasWriteAudit = await db.SecretAuditEntries
            .AnyAsync(x => x.VaultId == ApiTestFactory.VaultId &&
                           x.SecretName == "DB_PASSWORD" &&
                           x.Action == "SECRET_WRITE");
        Assert.True(hasWriteAudit);
    }

    [Fact]
    public async Task ReadMetadataEndpoints_ShouldNotExposePlainValue_AndShouldWriteAudit()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/API_TOKEN",
            new { value = "token-em-claro", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });

        var metadataResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets/API_TOKEN");
        Assert.Equal(HttpStatusCode.OK, metadataResponse.StatusCode);
        Assert.True(metadataResponse.Headers.CacheControl?.NoStore ?? false);

        var metadataJson = JsonDocument.Parse(await metadataResponse.Content.ReadAsStringAsync());
        Assert.False(metadataJson.RootElement.TryGetProperty("value", out _));
        Assert.True(metadataJson.RootElement.TryGetProperty("keyReference", out _));

        var versionsResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets/API_TOKEN/versions?includeRevoked=false&fromVersion=1&toVersion=10");
        Assert.Equal(HttpStatusCode.OK, versionsResponse.StatusCode);
        Assert.True(versionsResponse.Headers.CacheControl?.NoStore ?? false);

        var versionsJson = JsonDocument.Parse(await versionsResponse.Content.ReadAsStringAsync());
        Assert.True(versionsJson.RootElement.TryGetProperty("versions", out var versionsElement));
        Assert.True(versionsElement.GetArrayLength() >= 1);

        var auditResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets/API_TOKEN/audit?take=100");
        Assert.Equal(HttpStatusCode.OK, auditResponse.StatusCode);
        Assert.True(auditResponse.Headers.CacheControl?.NoStore ?? false);

        var auditJson = JsonDocument.Parse(await auditResponse.Content.ReadAsStringAsync());
        Assert.True(auditJson.RootElement.TryGetProperty("entries", out var entriesElement));
        Assert.True(entriesElement.GetArrayLength() >= 2);
    }

    [Fact]
    public async Task ListMetadata_ShouldReturnPaginatedFilteredStableOrderedResult_AndWriteAudit()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/LIST_META_ALPHA",
            new { value = "alpha", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });
        await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/LIST_META_BRAVO",
            new { value = "bravo", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });
        await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/LIST_META_CHARLIE",
            new { value = "charlie", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE vault_secrets
                SET Status = {(int)Domain.vault.Status.Disabled}
                WHERE VaultId = {ApiTestFactory.VaultId} AND Name = {"LIST_META_BRAVO"};
                """);
        }

        var response = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets?name=LIST_META&status=Active&page=1&pageSize=2&orderBy=name&orderDirection=asc");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore ?? false);

        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = payload.RootElement;

        Assert.Equal(2, root.GetProperty("totalCount").GetInt32());
        Assert.Equal(1, root.GetProperty("totalPages").GetInt32());
        Assert.Equal(2, root.GetProperty("pageSize").GetInt32());

        var items = root.GetProperty("items");
        Assert.Equal(2, items.GetArrayLength());
        Assert.Equal("LIST_META_ALPHA", items[0].GetProperty("name").GetString());
        Assert.Equal("LIST_META_CHARLIE", items[1].GetProperty("name").GetString());
        Assert.False(items[0].TryGetProperty("value", out _));

        using var scope2 = _factory.Services.CreateScope();
        var db2 = scope2.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var hasListAudit = await db2.SecretAuditEntries
            .AnyAsync(x => x.VaultId == ApiTestFactory.VaultId &&
                           x.SecretName == null &&
                           x.Action == "SECRET_LIST_METADATA");
        Assert.True(hasListAudit);
    }

    [Fact]
    public async Task ListMetadata_ShouldReturnBadRequest_WhenParametersAreInvalid()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var invalidPage = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets?page=0");
        var invalidPageSize = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets?pageSize=1000");
        var invalidStatus = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets?status=NotAStatus");
        var invalidOrderBy = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets?orderBy=createdAt");
        var invalidOrderDirection = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets?orderDirection=sideways");

        Assert.Equal(HttpStatusCode.BadRequest, invalidPage.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidPageSize.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidStatus.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidOrderBy.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidOrderDirection.StatusCode);
    }

    [Fact]
    public async Task PutSecret_OnUnhandledException_ShouldNotExposeSecretInResponse()
    {
        await _factory.EnsureInitializedAsync();

        const string leakedSecret = "NaoPodeVazar#123";
        using var client = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<ISecretProtector>();
                services.AddSingleton<ISecretProtector>(new ThrowingSecretProtector());
            });
        }).CreateClient();

        var response = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/SHOULD_FAIL",
            new
            {
                value = leakedSecret,
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);

        var payload = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(leakedSecret, payload, StringComparison.Ordinal);
        Assert.Contains("traceId", payload, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SecretEndpoints_ShouldReturnForbidden_WhenNoActiveAdMapForVault()
    {
        await _factory.EnsureInitializedAsync();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            db.ADMaps.RemoveRange(db.ADMaps.Where(x => x.VaultId == ApiTestFactory.VaultId));
            await db.SaveChangesAsync();
        }

        using var client = _factory.CreateClient();
        var response = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets/ANY_SECRET");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        using var scope2 = _factory.Services.CreateScope();
        var db2 = scope2.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var hasDeniedAudit = await db2.SecretAuditEntries
            .AnyAsync(x => x.VaultId == ApiTestFactory.VaultId &&
                           x.SecretName == "ANY_SECRET" &&
                           x.Action == "SECRET_ACCESS_DENIED");
        Assert.True(hasDeniedAudit);
    }

    [Fact]
    public async Task SecretWrite_ShouldReturnForbidden_WhenVaultIsNotActive()
    {
        await _factory.EnsureInitializedAsync();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var vault = await db.Vaults.SingleAsync(x => x.Id == ApiTestFactory.VaultId);
            vault.Status = Domain.vault.Status.Disabled;
            await db.SaveChangesAsync();
        }

        using var client = _factory.CreateClient();
        var response = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/DB_PASSWORD",
            new
            {
                value = "Senha@SuperSecreta!",
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task RequestSecretValue_WithValidProof_ShouldReturnPlainValue_AndWriteAudit()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        const string expectedSecret = "valor-super-secreto";

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET",
            new
            {
                value = expectedSecret,
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        var (nonce, issuedAtUtc) = await IssueVaultRequestChallengeAsync(client);
        var proof = BuildVaultSecretRequestProof(
            vaultId: ApiTestFactory.VaultId,
            secretName: "APP_SECRET",
            clientId: VaultRequestClientId,
            subject: AuthenticatedSubject,
            reason: "Incidente em producao",
            ticket: "INC-1234",
            nonce: nonce,
            issuedAtUtc: issuedAtUtc,
            clientSecret: VaultRequestClientSecret);

        var requestResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Incidente em producao",
                ticket = "INC-1234",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        Assert.Equal(HttpStatusCode.OK, requestResponse.StatusCode);
        Assert.True(requestResponse.Headers.CacheControl?.NoStore ?? false);

        var payload = JsonDocument.Parse(await requestResponse.Content.ReadAsStringAsync());
        Assert.Equal(expectedSecret, payload.RootElement.GetProperty("value").GetString());

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var hasRequestAudit = await db.SecretAuditEntries
            .AnyAsync(x => x.VaultId == ApiTestFactory.VaultId &&
                           x.SecretName == "APP_SECRET" &&
                           x.Action == "SECRET_REQUEST_VALUE");
        Assert.True(hasRequestAudit);
    }

    [Fact]
    public async Task RequestSecretValue_ShouldReturnBadRequest_WhenContractIsIncompleteOrUnsupported()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_CONTRACT",
            new
            {
                value = "valor-super-secreto-contrato",
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        var (nonce, issuedAtUtc) = await IssueVaultRequestChallengeAsync(client);
        var proof = BuildVaultSecretRequestProof(
            vaultId: ApiTestFactory.VaultId,
            secretName: "APP_SECRET_CONTRACT",
            clientId: VaultRequestClientId,
            subject: AuthenticatedSubject,
            reason: "Validacao contratual",
            ticket: "INC-CONTRACT-01",
            nonce: nonce,
            issuedAtUtc: issuedAtUtc,
            clientSecret: VaultRequestClientSecret);

        var missingTicket = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_CONTRACT/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Validacao contratual",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        var missingIssuedAt = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_CONTRACT/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Validacao contratual",
                ticket = "INC-CONTRACT-01",
                clientId = VaultRequestClientId,
                nonce,
                proof
            });

        var missingContractVersion = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_CONTRACT/request",
            new
            {
                reason = "Validacao contratual",
                ticket = "INC-CONTRACT-01",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        var unsupportedContractVersion = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_CONTRACT/request",
            new
            {
                contractVersion = "v2",
                reason = "Validacao contratual",
                ticket = "INC-CONTRACT-01",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        Assert.Equal(HttpStatusCode.BadRequest, missingTicket.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, missingIssuedAt.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, missingContractVersion.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unsupportedContractVersion.StatusCode);
    }

    [Fact]
    public async Task RequestSecretValue_ShouldRejectReplayWhenNonceIsReused()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        const string expectedSecret = "valor-super-secreto-replay";

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_REPLAY",
            new
            {
                value = expectedSecret,
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        var (nonce, issuedAtUtc) = await IssueVaultRequestChallengeAsync(client);
        var proof = BuildVaultSecretRequestProof(
            vaultId: ApiTestFactory.VaultId,
            secretName: "APP_SECRET_REPLAY",
            clientId: VaultRequestClientId,
            subject: AuthenticatedSubject,
            reason: "Investigacao de incidente",
            ticket: "INC-REPLAY",
            nonce: nonce,
            issuedAtUtc: issuedAtUtc,
            clientSecret: VaultRequestClientSecret);

        var first = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_REPLAY/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Investigacao de incidente",
                ticket = "INC-REPLAY",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        var replay = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_REPLAY/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Investigacao de incidente",
                ticket = "INC-REPLAY",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task RequestSecretValue_WithUnknownClient_ShouldNotConsumeValidNonce()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        const string expectedSecret = "valor-super-secreto-unknown-client";

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_UNKNOWN_CLIENT",
            new
            {
                value = expectedSecret,
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            });

        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        var (nonce, issuedAtUtc) = await IssueVaultRequestChallengeAsync(client);
        var validProof = BuildVaultSecretRequestProof(
            vaultId: ApiTestFactory.VaultId,
            secretName: "APP_SECRET_UNKNOWN_CLIENT",
            clientId: VaultRequestClientId,
            subject: AuthenticatedSubject,
            reason: "Producao indisponivel",
            ticket: "INC-UNKNOWN-CLIENT",
            nonce: nonce,
            issuedAtUtc: issuedAtUtc,
            clientSecret: VaultRequestClientSecret);

        var invalidAttempt = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_UNKNOWN_CLIENT/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Producao indisponivel",
                ticket = "INC-UNKNOWN-CLIENT",
                clientId = "unknown-client",
                nonce,
                issuedAt = issuedAtUtc,
                proof = "invalid-proof"
            });

        Assert.Equal(HttpStatusCode.Unauthorized, invalidAttempt.StatusCode);

        var validAttempt = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET_UNKNOWN_CLIENT/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Producao indisponivel",
                ticket = "INC-UNKNOWN-CLIENT",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof = validProof
            });

        Assert.Equal(HttpStatusCode.OK, validAttempt.StatusCode);

        using var payload = JsonDocument.Parse(await validAttempt.Content.ReadAsStringAsync());
        Assert.Equal(expectedSecret, payload.RootElement.GetProperty("value").GetString());
    }

    private static async Task<(string Nonce, DateTimeOffset IssuedAtUtc)> IssueVaultRequestChallengeAsync(HttpClient client)
    {
        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = VaultRequestClientId,
            subject = AuthenticatedSubject,
            audience = NonceChallengeAudiences.VaultSecretRequest
        });

        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();

        Assert.False(string.IsNullOrWhiteSpace(nonce));

        return (nonce!, issuedAtUtc);
    }

    private static string BuildVaultSecretRequestProof(
        Guid vaultId,
        string secretName,
        string clientId,
        string subject,
        string reason,
        string ticket,
        string nonce,
        DateTimeOffset issuedAtUtc,
        string clientSecret)
    {
        var payload = $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|{subject.Trim().ToUpperInvariant()}|{reason.Trim()}|{NormalizeTicketId(ticket)}|{nonce.Trim()}|{issuedAtUtc:O}";
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);

        using var hmac = new HMACSHA256(secretBytes);
        var hash = hmac.ComputeHash(payloadBytes);

        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string NormalizeTicketId(string? ticketId)
    {
        return string.IsNullOrWhiteSpace(ticketId) ? "-" : ticketId.Trim();
    }

    private sealed class ThrowingSecretProtector : ISecretProtector
    {
        public ValueTask<ProtectedSecret> ProtectAsync(
            string plaintext,
            SecretProtectionContext? context = null,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException($"Secret leak attempt: {plaintext}");
        }

        public ValueTask<string> UnprotectAsync(
            ProtectedSecret protectedSecret,
            SecretProtectionContext? context = null,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("Not used in this test.");
        }
    }
}
