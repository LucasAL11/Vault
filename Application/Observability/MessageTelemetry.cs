using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Application.Observability;

public sealed class MessageTelemetry : IDisposable
{
    private readonly Meter _meter;
    private readonly ActivitySource _activitySource;
    private readonly Counter<long> _messages;
    private readonly Counter<long> _failures;
    private readonly Histogram<double> _durationMs;

    public MessageTelemetry()
    {
        _meter = new Meter("WebApplication1.Application", "1.0.0");
        _activitySource = new ActivitySource("WebApplication1.Application");

        _messages = _meter.CreateCounter<long>("application_handler_requests_total");
        _failures = _meter.CreateCounter<long>("application_handler_failures_total");
        _durationMs = _meter.CreateHistogram<double>("application_handler_duration_ms");
    }

    public Activity? StartHandlerActivity(string messageKind, string messageName)
        => _activitySource.StartActivity($"handler {messageKind} {messageName}", ActivityKind.Internal);

    public void TrackResult(
        string messageKind,
        string messageName,
        bool success,
        string? errorCode,
        double elapsedMilliseconds)
    {
        var outcome = success ? "success" : "failure";

        TagList tags = default;
        tags.Add("message_kind", messageKind);
        tags.Add("message_name", messageName);
        tags.Add("outcome", outcome);
        if (!string.IsNullOrWhiteSpace(errorCode))
        {
            tags.Add("error_code", errorCode);
        }

        _messages.Add(1, tags);
        _durationMs.Record(elapsedMilliseconds, tags);

        if (!success)
        {
            _failures.Add(1, tags);
        }
    }

    public void TrackException(
        string messageKind,
        string messageName,
        string exceptionType,
        double elapsedMilliseconds)
    {
        TagList tags = default;
        tags.Add("message_kind", messageKind);
        tags.Add("message_name", messageName);
        tags.Add("outcome", "exception");
        tags.Add("exception_type", exceptionType);

        _messages.Add(1, tags);
        _failures.Add(1, tags);
        _durationMs.Record(elapsedMilliseconds, tags);
    }

    public void Dispose()
    {
        _activitySource.Dispose();
        _meter.Dispose();
    }
}
