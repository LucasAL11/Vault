using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Api.Observability;

public sealed class SecurityMetrics : IDisposable
{
    private readonly Meter _meter;
    private readonly Counter<long> _requests;
    private readonly Counter<long> _failures;
    private readonly Counter<long> _authDecisions;
    private readonly Histogram<double> _durationMs;

    public SecurityMetrics()
    {
        _meter = new Meter("WebApplication1.Security", "1.0.0");
        _requests = _meter.CreateCounter<long>("security_requests_total");
        _failures = _meter.CreateCounter<long>("security_failures_total");
        _authDecisions = _meter.CreateCounter<long>("security_auth_decisions_total");
        _durationMs = _meter.CreateHistogram<double>("security_request_duration_ms");
    }

    public void TrackAuthorizationDecision(
        string decision,
        string method,
        string route,
        string? authType,
        string? failedRequirements)
    {
        TagList tags = default;
        tags.Add("decision", decision);
        tags.Add("method", method);
        tags.Add("route", route);
        tags.Add("auth_type", authType ?? "none");

        if (!string.IsNullOrWhiteSpace(failedRequirements))
        {
            tags.Add("failed_requirements", failedRequirements);
        }

        _authDecisions.Add(1, tags);
    }

    public void Track(
        string domain,
        string method,
        string route,
        int statusCode,
        double elapsedMilliseconds)
    {
        var outcome = statusCode switch
        {
            >= 200 and < 300 => "success",
            401 => "unauthorized",
            403 => "forbidden",
            >= 400 and < 500 => "client_error",
            >= 500 => "server_error",
            _ => "other"
        };

        TagList tags = default;
        tags.Add("domain", domain);
        tags.Add("method", method);
        tags.Add("route", route);
        tags.Add("status_code", statusCode);
        tags.Add("outcome", outcome);

        _requests.Add(1, tags);
        _durationMs.Record(elapsedMilliseconds, tags);

        if (statusCode >= 400)
        {
            _failures.Add(1, tags);
        }
    }

    public void Dispose()
    {
        _meter.Dispose();
    }
}
