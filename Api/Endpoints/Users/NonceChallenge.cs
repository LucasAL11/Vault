using System.Security.Cryptography;
using Api.Security;
using Application.Abstractions.Security;
using Infrastructure.Security;
using Microsoft.Extensions.Options;
using Shared;

namespace Api.Endpoints.Users;

public sealed class NonceChallenge : IEndpoint
{
    private const int NonceSizeBytes = 32;
    private const int MaxAttempts = 5;
    private const int MaxClientIdLength = 80;
    private const int MaxSubjectLength = 180;

    private sealed record Request(string? ClientId, string? Subject, string? Audience);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/auth/challenge", async (
            Request? request,
            INonceStore nonceStore,
            IDateTimeProvider dateTimeProvider,
            IOptions<NonceStoreOptions> nonceOptions,
            HttpContext httpContext,
            ILogger<NonceChallenge> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            var now = dateTimeProvider.UtcNow;
            var ttlSeconds = Math.Max(1, nonceOptions.Value.TtlSeconds);
            var expiresAtUtc = now.AddSeconds(ttlSeconds);

            string? clientId = null;
            if (!string.IsNullOrWhiteSpace(request?.ClientId))
            {
                if (!InputValidation.TryNormalizeAsciiToken(request.ClientId, minLength: 1, maxLength: MaxClientIdLength, allowedSymbols: "._:-", out var normalizedClientId))
                {
                    return Results.BadRequest(new { message = "clientId is invalid." });
                }

                clientId = normalizedClientId;
            }

            string? requestedSubject = null;
            if (!string.IsNullOrWhiteSpace(request?.Subject))
            {
                if (!InputValidation.TryNormalizeText(request.Subject, minLength: 1, maxLength: MaxSubjectLength, out var normalizedRequestedSubject) ||
                    normalizedRequestedSubject.Contains('|'))
                {
                    return Results.BadRequest(new { message = "subject is invalid." });
                }

                requestedSubject = normalizedRequestedSubject;
            }

            if (!NonceChallengeAudiences.TryNormalize(request?.Audience, out var audience))
            {
                return Results.BadRequest(new { message = "audience is required and must be supported." });
            }

            if (!NonceChallengeScope.TryResolveSubject(httpContext, requestedSubject, out var subject))
            {
                return Results.BadRequest(new { message = "subject is required when request is anonymous." });
            }

            var scope = NonceChallengeScope.Build(
                httpContext,
                clientId,
                subject,
                audience);

            // DEBUG: log scope and IP for nonce mismatch investigation
            logger.LogWarning(
                "Challenge NONCE DEBUG: scope={Scope}, remoteIp={RemoteIp}, subject={Subject}, audience={Audience}, clientId={ClientId}",
                scope,
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "null",
                subject, audience, clientId);

            for (var attempt = 0; attempt < MaxAttempts; attempt++)
            {
                var nonceBytes = RandomNumberGenerator.GetBytes(NonceSizeBytes);
                var accepted = await nonceStore.TryAddAsync(scope, nonceBytes, cancellationToken);
                if (!accepted)
                {
                    continue;
                }

                return Results.Ok(new
                {
                    Nonce = ToBase64Url(nonceBytes),
                    Subject = subject,
                    Audience = audience,
                    IssuedAtUtc = now,
                    ExpiresAtUtc = expiresAtUtc,
                    TtlSeconds = ttlSeconds
                });
            }

            return Results.Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "Unable to issue nonce challenge.",
                detail: "Please retry.");
        }).AllowAnonymous().RequireRateLimiting("AuthChallengePolicy");
    }

    private static string ToBase64Url(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static void ApplyNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }
}
