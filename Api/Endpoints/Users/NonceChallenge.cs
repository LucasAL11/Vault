using System.Security.Cryptography;
using Application.Abstractions.Security;
using Infrastructure.Security;
using Microsoft.Extensions.Options;
using Shared;

namespace Api.Endpoints.Users;

public sealed class NonceChallenge : IEndpoint
{
    private const int NonceSizeBytes = 32;
    private const int MaxAttempts = 5;

    private sealed record Request(string? ClientId);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/auth/challenge", async (
            Request? request,
            INonceStore nonceStore,
            IDateTimeProvider dateTimeProvider,
            IOptions<NonceStoreOptions> nonceOptions,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            var now = dateTimeProvider.UtcNow;
            var ttlSeconds = Math.Max(1, nonceOptions.Value.TtlSeconds);
            var expiresAtUtc = now.AddSeconds(ttlSeconds);
            var scope = NonceChallengeScope.Build(httpContext, request?.ClientId);

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
