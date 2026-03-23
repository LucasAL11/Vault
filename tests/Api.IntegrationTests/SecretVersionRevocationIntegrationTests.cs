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

public sealed class SecretVersionRevocationIntegrationTests : IClassFixture<ApiTestFactory>
{
    private const string VaultRequestContractVersion = "v1";
    private const string VaultRequestClientId = "local-dev-client";
    private const string VaultRequestClientSecret = "dev-shared-secret-please-rotate";
    private const string AuthenticatedSubject = "PLT\\integration.user";

    private readonly ApiTestFactory _factory;

    public SecretVersionRevocationIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task RevokeSecretVersion_ShouldReturnBadRequest_WhenReasonIsMissing()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REVOCATION_REASON_REQUIRED",
            new { value = "valor-para-revogacao", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });
        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        var revokeWithEmptyReason = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REVOCATION_REASON_REQUIRED/versions/1/revoke",
            new { reason = "" });
        var revokeWithoutReason = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REVOCATION_REASON_REQUIRED/versions/1/revoke",
            new { });

        Assert.Equal(HttpStatusCode.BadRequest, revokeWithEmptyReason.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, revokeWithoutReason.StatusCode);
    }

    [Fact]
    public async Task RevokeSecretVersion_ShouldBlockDelivery_AndWriteAuditedEventWithActor()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REVOCATION_BLOCKS_DELIVERY",
            new { value = "valor-revogado", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });
        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        const string revokeReason = "Credencial comprometida";
        var revokeResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REVOCATION_BLOCKS_DELIVERY/versions/1/revoke",
            new { reason = revokeReason });
        Assert.Equal(HttpStatusCode.OK, revokeResponse.StatusCode);
        Assert.True(revokeResponse.Headers.CacheControl?.NoStore ?? false);

        using (var revokePayload = JsonDocument.Parse(await revokeResponse.Content.ReadAsStringAsync()))
        {
            Assert.True(revokePayload.RootElement.GetProperty("isRevoked").GetBoolean());
            Assert.Equal(AuthenticatedSubject, revokePayload.RootElement.GetProperty("actor").GetString());
            Assert.Equal(revokeReason, revokePayload.RootElement.GetProperty("reason").GetString());
        }

        var (nonce, issuedAtUtc) = await IssueVaultRequestChallengeAsync(client);
        var proof = BuildVaultSecretRequestProof(
            vaultId: ApiTestFactory.VaultId,
            secretName: "REVOCATION_BLOCKS_DELIVERY",
            clientId: VaultRequestClientId,
            subject: AuthenticatedSubject,
            reason: "Leitura apos revogacao",
            ticket: "INC-REVOGADO-01",
            nonce: nonce,
            issuedAtUtc: issuedAtUtc,
            clientSecret: VaultRequestClientSecret);

        var requestResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REVOCATION_BLOCKS_DELIVERY/request",
            new
            {
                contractVersion = VaultRequestContractVersion,
                reason = "Leitura apos revogacao",
                ticket = "INC-REVOGADO-01",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });
        Assert.Equal(HttpStatusCode.NotFound, requestResponse.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var secret = await db.Secrets.SingleAsync(x =>
            x.VaultId == ApiTestFactory.VaultId &&
            x.Name == "REVOCATION_BLOCKS_DELIVERY");
        var revokedVersion = await db.SecretVersions.SingleAsync(x =>
            x.SecretId == secret.Id &&
            x.Version == 1);
        Assert.True(revokedVersion.IsRevoked);

        var revokeAudit = (await db.SecretAuditEntries
                .Where(x =>
                    x.VaultId == ApiTestFactory.VaultId &&
                    x.SecretName == "REVOCATION_BLOCKS_DELIVERY" &&
                    x.Action == "SECRET_VERSION_REVOKE")
                .ToListAsync())
            .OrderByDescending(x => x.OccurredAtUtc)
            .FirstOrDefault();
        Assert.NotNull(revokeAudit);
        Assert.Equal(AuthenticatedSubject, revokeAudit!.Actor);
        Assert.Contains("version=1", revokeAudit.Details ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains($"reason={revokeReason}", revokeAudit.Details ?? string.Empty, StringComparison.Ordinal);
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
}
