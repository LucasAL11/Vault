using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public sealed class SecurityMetricsIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public SecurityMetricsIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Should_Record_Request_And_Duration_Metrics_For_Auth_And_Secrets()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();
        using var collector = new SecurityMetricsCollector();

        var authResponse = await client.GetAsync("/users/groups");
        var secretResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/secrets/METRIC_SECRET",
            new { value = "metric-secret-value", contentType = "text/plain", expiresUtc = (DateTimeOffset?)null });

        Assert.Equal(HttpStatusCode.OK, authResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, secretResponse.StatusCode);

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "security_requests_total" &&
            x.Domain == "auth" &&
            x.StatusCode == 200 &&
            x.Outcome == "success");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "security_requests_total" &&
            x.Domain == "secrets" &&
            x.StatusCode == 200 &&
            x.Outcome == "success");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "security_request_duration_ms" &&
            x.Domain == "auth" &&
            x.Value > 0);

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "security_request_duration_ms" &&
            x.Domain == "secrets" &&
            x.Value > 0);
    }

    [Fact]
    public async Task Should_Record_Failure_Metric_For_Secrets_NotFound()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();
        using var collector = new SecurityMetricsCollector();

        var response = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/secrets/SECRET_DOES_NOT_EXIST");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "security_failures_total" &&
            x.Domain == "secrets" &&
            x.StatusCode == 404 &&
            x.Outcome == "client_error");
    }

    private sealed class SecurityMetricsCollector : IDisposable
    {
        private readonly MeterListener _listener;
        private readonly ConcurrentBag<MetricEntry> _entries = new();

        public IReadOnlyCollection<MetricEntry> Entries => _entries.ToArray();

        public SecurityMetricsCollector()
        {
            _listener = new MeterListener();
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "WebApplication1.Security")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };

            _listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
            {
                _entries.Add(MetricEntry.Create(instrument.Name, measurement, tags));
            });

            _listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, state) =>
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
        string? Domain,
        string? Method,
        string? Route,
        int? StatusCode,
        string? Outcome)
    {
        public static MetricEntry Create(
            string instrumentName,
            double measurement,
            ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            return new MetricEntry(
                instrumentName,
                measurement,
                GetString(tags, "domain"),
                GetString(tags, "method"),
                GetString(tags, "route"),
                GetInt(tags, "status_code"),
                GetString(tags, "outcome"));
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

        private static int? GetInt(ReadOnlySpan<KeyValuePair<string, object?>> tags, string key)
        {
            var value = GetString(tags, key);
            return int.TryParse(value, out var parsed) ? parsed : null;
        }
    }
}
