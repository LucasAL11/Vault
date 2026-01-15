using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Logging;
using Serilog.Context;

namespace Api.Middleware;

public class RequestContextLoggingMiddleware(RequestDelegate next)
{
    private const string CorrelationIdHeaderName = "Correlation-ID";

    public Task Invoke(HttpContext httpContext)
    {
        using (LogContext.PushProperty("CorrelationId", httpContext.TraceIdentifier))
        {
            return next.Invoke(httpContext);
        }
    }

    private static string GetCorrelationId(HttpContext httpContext)
    {
        httpContext
            .Request
            .Headers
            .TryGetValue(CorrelationIdHeaderName, out var correlationId);
        
        return correlationId.FirstOrDefault() ?? httpContext.TraceIdentifier;
    }
}