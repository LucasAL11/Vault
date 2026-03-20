using System.Security.Cryptography;
using System.Text;
using Api.Endpoints.Users;
using Application.Abstractions.Security;

namespace Api.Endpoints.Cryptography;

public sealed class HashSecret : IEndpoint
{
    private sealed record Request(string Secret, string ClientId, string Nonce);

    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("/Cryptography/hash", async (
            Request request,
            INonceStore nonceStore,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (string.IsNullOrWhiteSpace(request.Secret))
            {
                return Results.BadRequest(new { Error = "secret is required" });
            }

            if (string.IsNullOrWhiteSpace(request.ClientId))
            {
                return Results.BadRequest(new { Error = "clientId is required" });
            }

            if (!TryFromBase64Url(request.Nonce, out var nonceBytes))
            {
                return Results.BadRequest(new { Error = "nonce is invalid" });
            }

            if (!NonceChallengeScope.TryResolveSubject(httpContext, requestedSubject: null, out var subject))
            {
                return Results.Unauthorized();
            }

            var scope = NonceChallengeScope.Build(
                httpContext,
                request.ClientId,
                subject,
                NonceChallengeAudiences.CryptographyHash);
            var consumed = await nonceStore.TryConsumeAsync(scope, nonceBytes, cancellationToken);
            if (!consumed)
            {
                return Results.Unauthorized();
            }

            byte[] secretBytes = Encoding.UTF8.GetBytes(request.Secret);
            byte[] hashBytes = SHA256.HashData(secretBytes);
            string hashBase64 = Convert.ToBase64String(hashBytes);
            string hashHex = Convert.ToHexString(hashBytes).ToLowerInvariant();

            return Results.Ok(new
            {
                HashBase64 = hashBase64,
                HashHex = hashHex
            });
        }).RequireRateLimiting("ZkSensitivePolicy");
    }

    private static bool TryFromBase64Url(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

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
}
