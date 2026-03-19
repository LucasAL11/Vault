using Application.Abstractions.Security;
using Shared;

namespace Api.Endpoints.Users;

public sealed class NonceChallengeVerify : IEndpoint
{
    private sealed record Request(string Nonce, string? ClientId);

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

            if (!TryFromBase64Url(request.Nonce, out var nonceBytes))
            {
                return Results.BadRequest(new { message = "nonce is invalid." });
            }

            var scope = NonceChallengeScope.Build(httpContext, request.ClientId);
            var consumed = await nonceStore.TryConsumeAsync(scope, nonceBytes, cancellationToken);

            return consumed
                ? Results.Ok(new { valid = true })
                : Results.Ok(new { valid = false });
        }).AllowAnonymous();
    }

    private static bool TryFromBase64Url(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();

        var normalized = input.Replace('-', '+').Replace('_', '/');
        switch (normalized.Length % 4)
        {
            case 2:
                normalized += "==";
                break;
            case 3:
                normalized += "=";
                break;
            case 1:
                return false;
        }

        try
        {
            bytes = Convert.FromBase64String(normalized);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static void ApplyNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }
}
