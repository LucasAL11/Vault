using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Api.IntegrationTests.Infrastructure;
using Api.Endpoints.Users;
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
        var response = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "web-client",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
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

        var firstResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "mobile-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        var secondResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "mobile-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });

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

        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var verifyOk = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        var verifyReplay = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
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
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task VerifyChallenge_WithDifferentAudience_ShouldReturnInvalidWithoutConsuming()
    {
        using var client = _factory.CreateClient();

        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var wrongAudience = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeRespond
        });

        var rightAudience = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });

        using var wrongJson = JsonDocument.Parse(await wrongAudience.Content.ReadAsStringAsync());
        using var rightJson = JsonDocument.Parse(await rightAudience.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, wrongAudience.StatusCode);
        Assert.Equal(HttpStatusCode.OK, rightAudience.StatusCode);
        Assert.False(wrongJson.RootElement.GetProperty("valid").GetBoolean());
        Assert.True(rightJson.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task VerifyChallenge_WithDifferentSubject_ShouldReturnInvalidWithoutConsuming()
    {
        using var client = _factory.CreateClient();

        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "desktop-app",
            subject = "PLT\\expected.user",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var wrongSubject = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app",
            subject = "PLT\\other.user",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });

        var rightSubject = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "desktop-app",
            subject = "PLT\\expected.user",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });

        using var wrongJson = JsonDocument.Parse(await wrongSubject.Content.ReadAsStringAsync());
        using var rightJson = JsonDocument.Parse(await rightSubject.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, wrongSubject.StatusCode);
        Assert.Equal(HttpStatusCode.OK, rightSubject.StatusCode);
        Assert.False(wrongJson.RootElement.GetProperty("valid").GetBoolean());
        Assert.True(rightJson.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task NonceIssuedForHashAudience_ShouldNotAuthorizeProveEndpoint_AndShouldRemainValidForHash()
    {
        using var client = _factory.CreateClient();

        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "zk-client",
            audience = NonceChallengeAudiences.CryptographyHash
        });
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var wrongEndpointAttempt = await client.PostAsJsonAsync("/Cryptography/zk", new
        {
            secret = "proof-secret",
            hashPublic = "invalid-hash",
            clientId = "zk-client",
            nonce
        });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongEndpointAttempt.StatusCode);

        var correctEndpointAttempt = await client.PostAsJsonAsync("/Cryptography/hash", new
        {
            secret = "proof-secret",
            clientId = "zk-client",
            nonce
        });
        Assert.Equal(HttpStatusCode.OK, correctEndpointAttempt.StatusCode);
    }

    [Fact]
    public async Task NonceIssuedForVerifyAudience_ShouldNotAuthenticateRespondEndpoint_AndShouldRemainValidForVerify()
    {
        using var client = _factory.CreateClient();

        const string username = "lucas.luna";
        const string domain = "PLT";

        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var signature = BuildSignature(
            "local-dev-client",
            username,
            domain,
            nonce!,
            issuedAtUtc,
            "dev-shared-secret-please-rotate");

        var wrongEndpointAttempt = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature
        });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongEndpointAttempt.StatusCode);

        var correctEndpointAttempt = await client.PostAsJsonAsync("/auth/challenge/verify", new
        {
            nonce,
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeVerify
        });
        Assert.Equal(HttpStatusCode.OK, correctEndpointAttempt.StatusCode);

        using var verifyJson = JsonDocument.Parse(await correctEndpointAttempt.Content.ReadAsStringAsync());
        Assert.True(verifyJson.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task RespondChallenge_WithValidSignature_ShouldReturnAccessToken()
    {
        using var client = _factory.CreateClient();

        const string username = "lucas.luna";
        const string domain = "PLT";
        var challenge = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeRespond
        });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

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

        const string username = "lucas.luna";
        const string domain = "PLT";
        var challenge = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeRespond
        });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();

        var validSignature = BuildSignature("local-dev-client", username, domain, nonce!, issuedAtUtc, "dev-shared-secret-please-rotate");
        var response = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature = validSignature + "tampered"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RespondChallenge_WithUnknownClientId_ShouldNotConsumeValidNonce()
    {
        using var client = _factory.CreateClient();

        const string username = "lucas.luna";
        const string domain = "PLT";
        var challenge = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeRespond
        });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
        Assert.False(string.IsNullOrWhiteSpace(nonce));

        var invalidClientSignature = BuildSignature(
            "unknown-client",
            username,
            domain,
            nonce!,
            issuedAtUtc,
            "random-secret");

        var unauthorizedAttempt = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "unknown-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature = invalidClientSignature
        });
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorizedAttempt.StatusCode);

        var validSignature = BuildSignature(
            "local-dev-client",
            username,
            domain,
            nonce!,
            issuedAtUtc,
            "dev-shared-secret-please-rotate");

        var validAttempt = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
            issuedAtUtc,
            nonce,
            signature = validSignature
        });
        Assert.Equal(HttpStatusCode.OK, validAttempt.StatusCode);
    }

    [Fact]
    public async Task RespondChallenge_ShouldRejectReplayAfterFirstUse()
    {
        using var client = _factory.CreateClient();

        const string username = "lucas.luna";
        const string domain = "PLT";
        var challenge = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeRespond
        });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset();
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

        const string username = "lucas.luna";
        const string domain = "PLT";
        var challenge = await client.PostAsJsonAsync("/auth/challenge", new
        {
            clientId = "local-dev-client",
            subject = $"{domain}\\{username}",
            audience = NonceChallengeAudiences.AuthChallengeRespond
        });
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var challengeJson = JsonDocument.Parse(await challenge.Content.ReadAsStringAsync());
        var nonce = challengeJson.RootElement.GetProperty("nonce").GetString();
        var issuedAtUtc = challengeJson.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset().AddMinutes(-10);

        var signature = BuildSignature(
            "local-dev-client",
            username,
            domain,
            nonce!,
            issuedAtUtc,
            "dev-shared-secret-please-rotate");

        var response = await client.PostAsJsonAsync("/auth/challenge/respond", new
        {
            clientId = "local-dev-client",
            username,
            domain,
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
