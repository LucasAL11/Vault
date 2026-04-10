using System.Net;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class SecurityHeadersCorsIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public SecurityHeadersCorsIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task GetDebugTime_ShouldReturnSecurityHeaders()
    {
        using var client = _factory.CreateClient();
        var response = await client.GetAsync("/debug/time");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("nosniff", GetSingleHeader(response, "X-Content-Type-Options"));
        Assert.Equal("DENY", GetSingleHeader(response, "X-Frame-Options"));
        Assert.Equal("no-referrer", GetSingleHeader(response, "Referrer-Policy"));
        Assert.Equal("same-origin", GetSingleHeader(response, "Cross-Origin-Opener-Policy"));
        Assert.Equal("same-origin", GetSingleHeader(response, "Cross-Origin-Resource-Policy"));
        Assert.Equal("none", GetSingleHeader(response, "X-Permitted-Cross-Domain-Policies"));
        Assert.True(response.Headers.Contains("Permissions-Policy"));
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
    }

    [Fact]
    public async Task GetDebugTime_WithAllowedOrigin_ShouldReturnCorsHeaders()
    {
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/debug/time");
        request.Headers.Add("Origin", "http://localhost:5065");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("http://localhost:5065", GetSingleHeader(response, "Access-Control-Allow-Origin"));
        Assert.Contains("X-API-Version", GetSingleHeader(response, "Access-Control-Expose-Headers"));
    }

    [Fact]
    public async Task GetDebugTime_WithBlockedOrigin_ShouldNotReturnCorsAllowOrigin()
    {
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/debug/time");
        request.Headers.Add("Origin", "https://malicious.example");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    private static string GetSingleHeader(HttpResponseMessage response, string headerName)
    {
        Assert.True(response.Headers.TryGetValues(headerName, out var values));
        return Assert.Single(values);
    }
}
