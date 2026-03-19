using Api.Infrastructure;
using Api.Observability;
using Api.Security;

namespace Api;

public static class DependencyInjection
{
    public static IServiceCollection AddPresentation(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();
        services.AddExceptionHandler<GlobalExceptionHandler>();
        services.AddProblemDetails();
        services.AddSingleton<SecurityMetrics>();
        services.Configure<AuthChallengeOptions>(_ => { });

        return services;
    }
}
