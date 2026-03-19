using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class NonceChallengeIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public NonceChallengeIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task PostChallenge_ShouldReturnNonceAndTtl_WithNoStoreHeaders()
    {
        using var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "web-client" });
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore ?? false);

        using var json = JsonDocument.Parse(payload);
        var root = json.RootElement;

        Assert.True(root.TryGetProperty("nonce", out var nonceProperty));
        Assert.False(string.IsNullOrWhiteSpace(nonceProperty.GetString()));
        Assert.True(root.TryGetProperty("ttlSeconds", out var ttlProperty));
        Assert.True(ttlProperty.GetInt32() > 0);
        Assert.True(root.TryGetProperty("issuedAtUtc", out _));
        Assert.True(root.TryGetProperty("expiresAtUtc", out _));
    }

    [Fact]
    public async Task PostChallenge_Twice_ShouldGenerateDifferentNonces()
    {
        using var client = _factory.CreateClient();

        var firstResponse = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "mobile-app" });
        var secondResponse = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "mobile-app" });

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);

        using var firstJson = JsonDocument.Parse(await firstResponse.Content.ReadAsStringAsync());
        using var secondJson = JsonDocument.Parse(await secondResponse.Content.ReadAsStringAsync());

        var nonce1 = firstJson.RootElement.GetProperty("nonce").GetString();
        var nonce2 = secondJson.RootElement.GetProperty("nonce").GetString();

        Assert.NotEqual(nonce1, nonce2);
    }

    [Fact]
    public async Task VerifyChallenge_ShouldConsumeNonce_AndRejectReplay()
    {
        using var client = _factory.CreateClient();

        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "desktop-app" });
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var verifyOk = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app"
        });
        var verifyReplay = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app"
        });

        Assert.Equal(HttpStatusCode.OK, verifyOk.StatusCode);
        Assert.Equal(HttpStatusCode.OK, verifyReplay.StatusCode);

        using var verifyOkJson = JsonDocument.Parse(await verifyOk.Content.ReadAsStringAsync());
        using var verifyReplayJson = JsonDocument.Parse(await verifyReplay.Content.ReadAsStringAsync());

        Assert.True(verifyOkJson.RootElement.GetProperty("valid").GetBoolean());
        Assert.False(verifyReplayJson.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task VerifyChallenge_WithInvalidNonce_ShouldReturnBadRequest()
    {
        using var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce = "%%%invalid-base64url%%%",
            clientId = "desktop-app"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RespondChallenge_WithValidSignature_ShouldReturnAccessToken()
    {
        using var client = _factory.CreateClient();

        var challenge = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "local-dev-client" });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        const string username = "lucas.luna";
        const string domain = "PLT";
        var signature = BuildSignature("local-dev-client", username, domain, nonce!, issuedAtUtc, "dev-shared-secret-please-rotate");

        var response = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.TryGetProperty("accessToken", out var tokenProperty));
        Assert.False(string.IsNullOrWhiteSpace(tokenProperty.GetString()));
    }

    [Fact]
    public async Task RespondChallenge_WithInvalidSignature_ShouldReturnUnauthorized()
    {
        using var client = _factory.CreateClient();

        var challenge = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "local-dev-client" });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();

        var validSignature = BuildSignature("local-dev-client", "lucas.luna", "PLT", nonce!, issuedAtUtc, "dev-shared-secret-please-rotate");
        var response = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username = "lucas.luna",
            domain = "PLT",
            issuedAtUtc,
            nonce,
            signature = validSignature + "tampered"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RespondChallenge_ShouldRejectReplayAfterFirstUse()
    {
        using var client = _factory.CreateClient();

        var challenge = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "local-dev-client" });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        const string username = "lucas.luna";
        const string domain = "PLT";
        var signature = BuildSignature("local-dev-client", username, domain, nonce!, issuedAtUtc, "dev-shared-secret-please-rotate");

        var first = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature
        });
        var replay = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature
        });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task RespondChallenge_WithClockSkewOutsideWindow_ShouldReturnUnauthorized()
    {
        using var client = _factory.CreateClient();

        var challenge = await client.PostAsJsonAsync("/auth/challenge", new { clientId = "local-dev-client" });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset().AddMinutes(-10);

        var signature = BuildSignature(
            "local-dev-client",
            "lucas.luna",
            "PLT",
            nonce!,
            issuedAtUtc,
            "dev-shared-secret-please-rotate");

        var response = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username = "lucas.luna",
            domain = "PLT",
            issuedAtUtc,
            nonce,
            signature
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static string BuildSignature(
        string clientId,
        string username,
        string domain,
        string nonce,
        DateTimeOffset issuedAtUtc,
        string secret)
    {
        var payload = $"{clientId}|{username}|{domain}|{nonce}|{issuedAtUtc:O}";
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var secretBytes = Encoding.UTF8.GetBytes(secret);

        using var hmac = new HMACSHA256(secretBytes);
        var hash = hmac.ComputeHash(payloadBytes);
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
