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
        Assert.True(response.Headers.Contains("Permissions-Policy"));
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
    }
    private static string GetSingleHeader(HttpResponseMessage response, string headerName)
    {
        Assert.True(response.Headers.TryGetValues(headerName, out var values));
        return Assert.Single(values);
    }
}
