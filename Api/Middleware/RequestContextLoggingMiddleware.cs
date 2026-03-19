using Serilog.Context;

namespace Api.Middleware;

public class RequestContextLoggingMiddleware(RequestDelegate next)
{
    public const string TraceIdHeaderName = "X-Trace-Id";

    public async Task Invoke(HttpContext httpContext)
    {
        var traceId = ResolveTraceId(httpContext);
        httpContext.TraceIdentifier = traceId;
        httpContext.Response.OnStarting(() =>
        {
            httpContext.Response.Headers[TraceIdHeaderName] = httpContext.TraceIdentifier;
            return Task.CompletedTask;
        });

        using (LogContext.PushProperty("TraceId", traceId))
        using (LogContext.PushProperty("CorrelationId", traceId))
        {
            await next.Invoke(httpContext);
        }
    }

    private static string ResolveTraceId(HttpContext httpContext)
    {
        var hasHeader = httpContext.Request.Headers.TryGetValue(TraceIdHeaderName, out var traceIdFromHeader);

        if (hasHeader && !string.IsNullOrWhiteSpace(traceIdFromHeader))
        {
            return traceIdFromHeader.ToString();
        }

        return httpContext.TraceIdentifier;
    }
}
