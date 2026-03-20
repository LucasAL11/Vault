using System.Net;
using System.Net.Http.Json;
using Api.Endpoints.Users;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class RateLimitingSensitiveRoutesIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public RateLimitingSensitiveRoutesIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task ChallengeEndpoint_ShouldReturn429_WhenLimitIsExceeded()
    {
        using var client = _factory.CreateClient();
        HttpResponseMessage? last = null;

        for (var i = 0; i < 31; i++)
        {
            last = await client.PostAsJsonAsync("/auth/challenge", new
            {
                clientId = "rate-limit-client",
                audience = NonceChallengeAudiences.AuthChallengeVerify
            });
        }

        Assert.NotNull(last);
        Assert.Equal(HttpStatusCode.TooManyRequests, last!.StatusCode);
        Assert.True(last.Headers.Contains("Retry-After"));
    }
}
