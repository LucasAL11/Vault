using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Api.Infrastructure;

internal sealed class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var problemDetails = new ProblemDetails();
        
        logger.LogError(exception, "Erro sem tratamento em GlobalExceptionHandler");

        switch (exception)
        {
            case ApplicationException appEx when appEx.Message.Contains("User id is unavailable"):
                problemDetails.Status = StatusCodes.Status401Unauthorized;
                problemDetails.Type = "https://datatracker.ietf.org/doc/html/rfc7235#section-3.1";
                problemDetails.Title = "Unauthorized";
                problemDetails.Detail = "User authentication required";
                break;
            
            default:
                problemDetails.Status = StatusCodes.Status500InternalServerError;
                problemDetails.Type = "https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.1";
                problemDetails.Title = "Server Failure";
                break;
        }
        
        httpContext.Response.StatusCode = problemDetails.Status.Value;
        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);
        return true;
    }
}