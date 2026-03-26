using Api.Security;
using Application.Abstractions.Security;
using Shared;

namespace Api.Endpoints.Users;

public sealed class NonceChallengeVerify : IEndpoint
{
    private const int MaxClientIdLength = 80;
    private const int MaxSubjectLength = 180;
    private const int MaxNonceEncodedLength = 128;
    private const int ExpectedNonceByteLength = 32;

    private sealed record Request(string? Nonce, string? ClientId, string? Subject, string? Audience);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/auth/challenge/verify", async (
            Request request,
            INonceStore nonceStore,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(request.Nonce))
            {
                return Results.BadRequest(new { message = "nonce is required." });
            }

            if (!InputValidation.TryDecodeBase64Url(
                    request.Nonce,
                    minByteLength: ExpectedNonceByteLength,
                    maxByteLength: ExpectedNonceByteLength,
                    maxEncodedLength: MaxNonceEncodedLength,
                    out _,
                    out var nonceBytes))
            {
                return Results.BadRequest(new { message = "nonce is invalid." });
            }

            string? normalizedClientId = null;
            if (!string.IsNullOrWhiteSpace(request.ClientId))
            {
                if (!InputValidation.TryNormalizeAsciiToken(request.ClientId, minLength: 1, maxLength: MaxClientIdLength, allowedSymbols: "._:-", out var validatedClientId))
                {
                    return Results.BadRequest(new { message = "clientId is invalid." });
                }

                normalizedClientId = validatedClientId;
            }

            string? normalizedRequestedSubject = null;
            if (!string.IsNullOrWhiteSpace(request.Subject))
            {
                if (!InputValidation.TryNormalizeText(request.Subject, minLength: 1, maxLength: MaxSubjectLength, out var validatedSubject) ||
                    validatedSubject.Contains('|'))
                {
                    return Results.BadRequest(new { message = "subject is invalid." });
                }

                normalizedRequestedSubject = validatedSubject;
            }

            if (!NonceChallengeAudiences.TryNormalize(request.Audience, out var audience))
            {
                return Results.BadRequest(new { message = "audience is required and must be supported." });
            }

            if (!NonceChallengeScope.TryResolveSubject(httpContext, normalizedRequestedSubject, out var subject))
            {
                return Results.BadRequest(new { message = "subject is required when request is anonymous." });
            }

            var scope = NonceChallengeScope.Build(
                httpContext,
                normalizedClientId,
                subject,
                audience);
            var consumed = await nonceStore.TryConsumeAsync(scope, nonceBytes, cancellationToken);

            return consumed
                ? Results.Ok(new { valid = true })
                : Results.Ok(new { valid = false });
        }).AllowAnonymous().RequireRateLimiting("AuthChallengeVerifyPolicy");
    }

    private static void ApplyNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }
}
