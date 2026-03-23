using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Api.Endpoints.Users;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class KeyProviderOperationsIntegrationTests : IClassFixture<ApiTestFactory>
{
    private const string ContractVersion = "v1";
    private const string VaultRequestClientId = "local-dev-client";
    private const string VaultRequestClientSecret = "dev-shared-secret-please-rotate";
    private const string AuthenticatedSubject = "PLT\\integration.user";

    private readonly ApiTestFactory _factory;

    public KeyProviderOperationsIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task ReEncrypt_ShouldBeIdempotent_AndKeepSecretReadable_WhenReprocessed()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var putResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REENCRYPT_SECRET",
            new { value = "valor-v1", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });
        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);

        var rotateResponse = await client.PostAsJsonAsync("/ops/key-provider/rotate", new
        {
            keyId = "test-key-v2"
        });
        Assert.Equal(HttpStatusCode.OK, rotateResponse.StatusCode);

        var firstReencrypt = await client.PostAsJsonAsync("/ops/key-provider/re-encrypt", new
        {
            vaultId = ApiTestFactory.VaultId,
            secretName = "REENCRYPT_SECRET",
            includeRevoked = false,
            includeExpired = false
        });
        var secondReencrypt = await client.PostAsJsonAsync("/ops/key-provider/re-encrypt", new
        {
            vaultId = ApiTestFactory.VaultId,
            secretName = "REENCRYPT_SECRET",
            includeRevoked = false,
            includeExpired = false
        });

        Assert.Equal(HttpStatusCode.OK, firstReencrypt.StatusCode);
        Assert.Equal(HttpStatusCode.OK, secondReencrypt.StatusCode);

        using var firstJson = JsonDocument.Parse(await firstReencrypt.Content.ReadAsStringAsync());
        using var secondJson = JsonDocument.Parse(await secondReencrypt.Content.ReadAsStringAsync());

        Assert.True(firstJson.RootElement.GetProperty("rotatedCount").GetInt32() > 0);
        Assert.Equal(0, secondJson.RootElement.GetProperty("rotatedCount").GetInt32());
        Assert.Equal("test-key-v2", secondJson.RootElement.GetProperty("currentKeyId").GetString());

        var versionsResponse = await client.GetAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REENCRYPT_SECRET/versions?includeRevoked=true");
        Assert.Equal(HttpStatusCode.OK, versionsResponse.StatusCode);

        using var versionsJson = JsonDocument.Parse(await versionsResponse.Content.ReadAsStringAsync());
        var versions = versionsJson.RootElement.GetProperty("versions");
        Assert.True(versions.GetArrayLength() >= 1);
        foreach (var version in versions.EnumerateArray())
        {
            Assert.Equal("test-key-v2", version.GetProperty("keyId").GetString());
        }

        var (nonce, issuedAtUtc) = await IssueVaultRequestChallengeAsync(client);
        var proof = BuildVaultSecretRequestProof(
            vaultId: ApiTestFactory.VaultId,
            secretName: "REENCRYPT_SECRET",
            clientId: VaultRequestClientId,
            subject: AuthenticatedSubject,
            reason: "Reprocessamento seguro",
            ticket: "INC-REENCRYPT-IDEMPOTENT",
            nonce: nonce,
            issuedAtUtc: issuedAtUtc,
            clientSecret: VaultRequestClientSecret);

        var readResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/REENCRYPT_SECRET/request",
            new
            {
                contractVersion = ContractVersion,
                reason = "Reprocessamento seguro",
                ticket = "INC-REENCRYPT-IDEMPOTENT",
                clientId = VaultRequestClientId,
                nonce,
                issuedAt = issuedAtUtc,
                proof
            });

        Assert.Equal(HttpStatusCode.OK, readResponse.StatusCode);
        using var readJson = JsonDocument.Parse(await readResponse.Content.ReadAsStringAsync());
        Assert.Equal("valor-v1", readJson.RootElement.GetProperty("value").GetString());
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
        var payload = $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|{subject.Trim().ToUpperInvariant()}|{reason.Trim()}|{NormalizeTicket(ticket)}|{nonce.Trim()}|{issuedAtUtc:O}";
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);

        using var hmac = new HMACSHA256(secretBytes);
        var hash = hmac.ComputeHash(payloadBytes);

        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string NormalizeTicket(string ticket)
    {
        return string.IsNullOrWhiteSpace(ticket) ? "-" : ticket.Trim();
    }
}
