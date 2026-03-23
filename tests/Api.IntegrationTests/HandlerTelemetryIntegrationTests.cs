using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
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
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();
        using var collector = new ApplicationMetricsCollector();

        var successResponse = await client.PostAsJsonAsync("/computers", new
        {
            name = "PC-METRICS-OK",
            cpuId = "BFEBFBFF000906ED",
            biosSerial = "12345678901234567890123456789012",
            diskSerial = "ABCDEFGHIJKLMNOPQRSTUVWX12345678",
            operatingSystem = "Windows 11 Pro",
            machineGuid = Guid.NewGuid().ToString()
        });
        Assert.Equal(HttpStatusCode.OK, successResponse.StatusCode);

        var failureResponse = await client.PostAsJsonAsync("/computers", new
        {
            name = "PC-METRICS-FAIL",
            cpuId = "BFEBFBFF000906ED",
            biosSerial = "short",
            diskSerial = "short",
            operatingSystem = "Windows 11 Pro",
            machineGuid = Guid.NewGuid().ToString()
        });
        Assert.Equal(HttpStatusCode.BadRequest, failureResponse.StatusCode);

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_requests_total" &&
            x.MessageKind == "command" &&
            x.MessageName == "RegisterComputerCommand" &&
            x.Outcome == "success");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_requests_total" &&
            x.MessageKind == "command" &&
            x.MessageName == "RegisterComputerCommand" &&
            x.Outcome == "failure");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_failures_total" &&
            x.MessageKind == "command" &&
            x.MessageName == "RegisterComputerCommand");

        Assert.Contains(collector.Entries, x =>
            x.InstrumentName == "application_handler_duration_ms" &&
            x.MessageKind == "command" &&
            x.MessageName == "RegisterComputerCommand" &&
            x.Value > 0);
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
