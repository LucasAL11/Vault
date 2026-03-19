using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Api.IntegrationTests.Infrastructure;
using Application.Abstractions.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Api.IntegrationTests;

public sealed class TraceCorrelationIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public TraceCorrelationIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Should_Return_Response_TraceId_Header_When_Request_Has_No_Trace_Header()
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/debug/time");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-Trace-Id", out var values));
        Assert.False(string.IsNullOrWhiteSpace(values.Single()));
    }

    [Fact]
    public async Task Should_Propagate_Client_TraceId_Header()
    {
        using var client = _factory.CreateClient();
        const string traceId = "trace-from-client-123";

        var request = new HttpRequestMessage(HttpMethod.Get, "/debug/time");
        request.Headers.Add("X-Trace-Id", traceId);
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-Trace-Id", out var values));
        Assert.Equal(traceId, values.Single());
    }

    [Fact]
    public async Task Should_Keep_Same_TraceId_In_Error_Response_Header_And_Payload()
    {
        await _factory.EnsureInitializedAsync();

        using var client = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<ISecretProtector>();
                services.AddSingleton<ISecretProtector>(new ThrowingSecretProtector());
            });
        }).CreateClient();

        const string traceId = "trace-for-error-500";
        var request = new HttpRequestMessage(HttpMethod.Put, $"/vaults/{ApiTestFactory.VaultId}/secrets/TRACE_FAIL")
        {
            Content = JsonContent.Create(new
            {
                value = "secret-value",
                contentType = "text/plain",
                expiresUtc = (DateTimeOffset?)null
            })
        };
        request.Headers.Add("X-Trace-Id", traceId);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-Trace-Id", out var values));
        Assert.Equal(traceId, values.Single());

        using var json = JsonDocument.Parse(body);
        Assert.True(json.RootElement.TryGetProperty("traceId", out var traceIdProperty));
        Assert.Equal(traceId, traceIdProperty.GetString());
    }

    private sealed class ThrowingSecretProtector : ISecretProtector
    {
        public ValueTask<ProtectedSecret> ProtectAsync(
            string plaintext,
            SecretProtectionContext? context = null,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("Intentional failure for traceId test.");
        }

        public ValueTask<string> UnprotectAsync(
            ProtectedSecret protectedSecret,
            SecretProtectionContext? context = null,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("Not used.");
        }
    }
}
