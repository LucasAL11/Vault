using System.Diagnostics;
using Api.Middleware;
using Api.Observability;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace Api.Security;

public sealed class StructuredAuthorizationResultHandler(
    ILogger<StructuredAuthorizationResultHandler> logger,
    SecurityMetrics securityMetrics)
    : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Challenged || authorizeResult.Forbidden)
        {
            var user = context.User;
            var failure = authorizeResult.AuthorizationFailure;
            var failedRequirements = failure?.FailedRequirements
                .Select(r => r.GetType().Name)
                .ToArray() ?? [];
            var decision = authorizeResult.Challenged ? "challenged" : "forbidden";
            var route = context.GetEndpoint()?.DisplayName
                        ?? context.Request.Path.Value
                        ?? "unknown";
            var failedRequirementsText = failedRequirements.Length == 0
                ? null
                : string.Join(",", failedRequirements);
            var correlationId = context.Items.TryGetValue(RequestContextLoggingMiddleware.CorrelationIdItemName, out var value)
                ? value?.ToString()
                : null;
            var spanId = Activity.Current?.SpanId.ToString();

            securityMetrics.TrackAuthorizationDecision(
                decision: decision,
                method: context.Request.Method,
                route: route,
                authType: user.Identity?.AuthenticationType,
                failedRequirements: failedRequirementsText);

            logger.LogInformation(
                "Authorization decision={Decision} path={Path} method={Method} endpoint={Endpoint} user={User} authType={AuthType} traceId={TraceId} correlationId={CorrelationId} spanId={SpanId} schemes={Schemes} failedRequirements={FailedRequirements}",
                decision,
                context.Request.Path.Value,
                context.Request.Method,
                context.GetEndpoint()?.DisplayName,
                user.Identity?.Name ?? "anonymous",
                user.Identity?.AuthenticationType ?? "none",
                context.TraceIdentifier,
                correlationId ?? context.TraceIdentifier,
                spanId ?? string.Empty,
                policy.AuthenticationSchemes,
                failedRequirements);
        }

        return _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}
