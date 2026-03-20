using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Api.Endpoints.Users;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class HandlerTelemetryIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public HandlerTelemetryIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Should_Record_Handler_Metrics_For_Success_And_Failure()
    {
        using var client = _factory.CreateClient();
        using var collector = new ApplicationMetricsCollector();

        var hashResponse = await client.PostAsJsonAsync("/Cryptography/hash", new
        {
            secret = "proof-secret",
            clientId = "zk-client",
            nonce = await RequestNonceAsync(client, "zk-client", NonceChallengeAudiences.CryptographyHash)
        });
        Assert.Equal(HttpStatusCode.OK, hashResponse.StatusCode);
        using var hashJson = JsonDocument.Parse(await hashResponse.Content.ReadAsStringAsync());
        var hashPublic = hashJson.RootElement.GetProperty("hashHex").GetString();
        Assert.False(string.IsNullOrWhiteSpace(hashPublic));

        var successResponse = await client.PostAsJsonAsync("/Cryptography/zk", new
        {
            secret = "proof-secret",
            hashPublic,
            clientId = "zk-client",
            nonce = await RequestNonceAsync(client, "zk-client", NonceChallengeAudiences.CryptographyProve)
        });
        Assert.Equal(HttpStatusCode.OK, successResponse.StatusCode);

        var failureResponse = await client.PostAsJsonAsync("/Cryptography/zk", new
        {
            secret = "",
            hashPublic,
            clientId = "zk-client",
            nonce = await RequestNonceAsync(client, "zk-client", NonceChallengeAudiences.CryptographyProve)
        });
        Assert.Equal(HttpStatusCode.BadRequest, failureResponse.StatusCode);

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_requests_total" &&
            x.MessageKind == "command" &&
            x.MessageName == "ProveCommand" &&
            x.Outcome == "success");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_requests_total" &&
            x.MessageKind == "command" &&
            x.MessageName == "ProveCommand" &&
            x.Outcome == "failure");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_failures_total" &&
            x.MessageKind == "command" &&
            x.MessageName == "ProveCommand");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_duration_ms" &&
            x.MessageKind == "command" &&
            x.MessageName == "ProveCommand" &&
            x.Value > 0);
    }

    private static async Task<string> RequestNonceAsync(HttpClient client, string clientId, string audience)
    {
        var challengeResponse = await client.PostAsJsonAsync("/auth/challenge", new { clientId, audience });
        challengeResponse.EnsureSuccessStatusCode();

        using var challengeJson = JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        return challengeJson.RootElement.GetProperty("nonce").GetString()!;
    }

    private sealed class ApplicationMetricsCollector : IDisposable
    {
        private readonly MeterListener _listener;
        private readonly ConcurrentBag<MetricEntry> _entries = new();

        public IReadOnlyCollection<MetricEntry> Entries => _entries.ToArray();

        public ApplicationMetricsCollector()
        {
            _listener = new MeterListener();
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "WebApplication1.Application")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };

            _listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
            {
                _entries.Add(MetricEntry.Create(instrument.Name, measurement, tags));
            });

            _listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
            {
                _entries.Add(MetricEntry.Create(instrument.Name, measurement, tags));
            });

            _listener.Start();
        }

        public void Dispose()
        {
            _listener.Dispose();
        }
    }

    private sealed record MetricEntry(
        string InstrumentName,
        double Value,
        string? MessageKind,
        string? MessageName,
        string? Outcome,
        string? ErrorCode)
    {
        public static MetricEntry Create(
            string instrumentName,
            double measurement,
            ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            return new MetricEntry(
                instrumentName,
                measurement,
                GetString(tags, "message_kind"),
                GetString(tags, "message_name"),
                GetString(tags, "outcome"),
                GetString(tags, "error_code"));
        }

        private static string? GetString(ReadOnlySpan<KeyValuePair<string, object?>> tags, string key)
        {
            for (var i = 0; i < tags.Length; i++)
            {
                var tag = tags[i];
                if (string.Equals(tag.Key, key, StringComparison.Ordinal))
                {
                    return tag.Value?.ToString();
                }
            }

            return null;
        }
    }
}
