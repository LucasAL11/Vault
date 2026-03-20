using System.Diagnostics;
using Serilog.Context;

namespace Api.Middleware;

public class RequestContextLoggingMiddleware(RequestDelegate next)
{
    public const string TraceIdHeaderName = "X-Trace-Id";
    public const string CorrelationIdHeaderName = "X-Correlation-Id";
    public const string CorrelationIdItemName = "CorrelationId";

    public async Task Invoke(HttpContext httpContext)
    {
        var traceId = ResolveTraceId(httpContext);
        var correlationId = ResolveCorrelationId(httpContext, traceId);
        var spanId = Activity.Current?.SpanId.ToString();

        httpContext.Items[CorrelationIdItemName] = correlationId;
        httpContext.TraceIdentifier = traceId;
        httpContext.Response.OnStarting(() =>
        {
            httpContext.Response.Headers[TraceIdHeaderName] = httpContext.TraceIdentifier;
            httpContext.Response.Headers[CorrelationIdHeaderName] = correlationId;
            return Task.CompletedTask;
        });

        using (LogContext.PushProperty("TraceId", traceId))
        using (LogContext.PushProperty("CorrelationId", correlationId))
        using (LogContext.PushProperty("SpanId", spanId ?? string.Empty))
        {
            await next.Invoke(httpContext);
        }
    }

    private static string ResolveTraceId(HttpContext httpContext)
    {
        if (httpContext.Request.Headers.TryGetValue(TraceIdHeaderName, out var traceIdFromHeader) &&
            !string.IsNullOrWhiteSpace(traceIdFromHeader))
        {
            return traceIdFromHeader.ToString();
        }

        return Activity.Current?.TraceId.ToString() ?? httpContext.TraceIdentifier;
    }

    private static string ResolveCorrelationId(HttpContext httpContext, string traceId)
    {
        if (httpContext.Request.Headers.TryGetValue(CorrelationIdHeaderName, out var correlationFromHeader) &&
            !string.IsNullOrWhiteSpace(correlationFromHeader))
        {
            return correlationFromHeader.ToString();
        }
        
        return traceId;
    }
}
