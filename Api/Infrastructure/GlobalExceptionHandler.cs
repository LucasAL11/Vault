using Api.Middleware;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Api.Infrastructure;

internal sealed class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var problemDetails = new ProblemDetails();
        var traceId = httpContext.TraceIdentifier;
        var correlationId = httpContext.Items.TryGetValue(RequestContextLoggingMiddleware.CorrelationIdItemName, out var value)
            ? value?.ToString() ?? traceId
            : traceId;

        logger.LogError(
            "Unhandled exception captured. TraceId={TraceId}, CorrelationId={CorrelationId}, Path={Path}, ExceptionType={ExceptionType}",
            traceId,
            correlationId,
            httpContext.Request.Path.Value,
            exception.GetType().FullName);

        switch (exception)
        {
            case ApplicationException appEx when appEx.Message.Contains("User id is unavailable"):
                problemDetails.Status = StatusCodes.Status401Unauthorized;
                problemDetails.Type = "https://datatracker.ietf.org/doc/html/rfc7235#section-3.1";
                problemDetails.Title = "Unauthorized";
                problemDetails.Detail = "Request failed.";
                break;

            default:
                problemDetails.Status = StatusCodes.Status500InternalServerError;
                problemDetails.Type = "https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.1";
                problemDetails.Title = "Server Failure";
                problemDetails.Detail = "Request failed.";
                break;
        }

        problemDetails.Extensions["traceId"] = traceId;
        problemDetails.Extensions["correlationId"] = correlationId;

        httpContext.Response.StatusCode = problemDetails.Status.Value;
        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);
        return true;
    }
}
