using Api.Middleware;

namespace Api.Extensions;

public static class MiddlewareExtensions
{
    public static IApplicationBuilder UserRequestLogging(this IApplicationBuilder builder)
    {
        builder.UseMiddleware<RequestContextLoggingMiddleware>();
        
        return builder;
    }
}