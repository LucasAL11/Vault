using System.Net;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class ApiVersioningIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public ApiVersioningIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task V1_Request_ShouldExposeApiVersionHeader()
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/debug/time");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-API-Version", out var values));
        Assert.Equal("v1", Assert.Single(values));
    }

}
