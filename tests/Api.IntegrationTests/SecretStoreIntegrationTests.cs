using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
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
    public async Task RequestSecretValue_ShouldReturnPlainValue_AndWriteAudit()
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

        var requestResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/APP_SECRET/request",
            new
            {
                reason = "Incidente em produção",
                ticketId = "INC-1234"
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
