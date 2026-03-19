using System.Security.Cryptography;
using System.Text;
using Api.Security;
using Application.Abstractions.Security;
using Application.Authentication;
using Infrastructure.Security;
using Microsoft.Extensions.Options;

namespace Api.Endpoints.Users;

public sealed class NonceChallengeRespond : IEndpoint
{
    private sealed record Request(
        string ClientId,
        string Username,
        string Domain,
        DateTimeOffset IssuedAtUtc,
        string Nonce,
        string Signature);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/auth/challenge/respond", async (
            Request request,
            INonceStore nonceStore,
            ITokenProvider tokenProvider,
            IOptions<AuthChallengeOptions> challengeOptions,
            IOptions<NonceStoreOptions> nonceStoreOptions,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(request.ClientId) ||
                string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.Domain) ||
                string.IsNullOrWhiteSpace(request.Nonce) ||
                string.IsNullOrWhiteSpace(request.Signature))
            {
                return Results.BadRequest(new { message = "clientId, username, domain, nonce and signature are required." });
            }

            if (!TryGetClientSecret(request.ClientId, challengeOptions.Value, out var clientSecret))
            {
                return Results.Unauthorized();
            }

            if (!TryFromBase64Url(request.Nonce, out var nonceBytes))
            {
                return Results.BadRequest(new { message = "nonce is invalid." });
            }

            var signaturePayload = BuildSignedPayload(
                request.ClientId,
                request.Username,
                request.Domain,
                request.Nonce,
                request.IssuedAtUtc);
            if (!IsSignatureValid(signaturePayload, request.Signature, clientSecret))
            {
                return Results.Unauthorized();
            }

            if (!IsWithinSkewWindow(
                    request.IssuedAtUtc,
                    challengeOptions.Value,
                    nonceStoreOptions.Value))
            {
                return Results.Unauthorized();
            }

            var scope = NonceChallengeScope.Build(httpContext, request.ClientId);
            var consumed = await nonceStore.TryConsumeAsync(scope, nonceBytes, cancellationToken);
            if (!consumed)
            {
                return Results.Unauthorized();
            }

            var loginResult = Domain.Users.Login.Create(request.Username);
            if (loginResult.IsFailure)
            {
                return Results.BadRequest(new { message = "username is invalid." });
            }

            var token = tokenProvider.Create(loginResult.Value);
            return Results.Ok(new
            {
                accessToken = token,
                tokenType = "Bearer",
                username = request.Username,
                domain = request.Domain
            });
        }).AllowAnonymous();
    }

    private static bool TryGetClientSecret(string clientId, AuthChallengeOptions options, out string secret)
    {
        secret = string.Empty;
        if (!options.ClientSecrets.TryGetValue(clientId, out var configuredSecret) ||
            string.IsNullOrWhiteSpace(configuredSecret))
        {
            return false;
        }

        secret = configuredSecret;
        return true;
    }

    private static bool IsSignatureValid(string payload, string signatureBase64Url, string clientSecret)
    {
        if (!TryFromBase64Url(signatureBase64Url, out var providedSignature))
        {
            return false;
        }

        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);

        using var hmac = new HMACSHA256(secretBytes);
        var expectedSignature = hmac.ComputeHash(payloadBytes);
        return CryptographicOperations.FixedTimeEquals(providedSignature, expectedSignature);
    }

    private static string BuildSignedPayload(
        string clientId,
        string username,
        string domain,
        string nonce,
        DateTimeOffset issuedAtUtc)
    {
        return $"{clientId}|{username}|{domain}|{nonce}|{issuedAtUtc:O}";
    }

    private static bool IsWithinSkewWindow(
        DateTimeOffset issuedAtUtc,
        AuthChallengeOptions challengeOptions,
        NonceStoreOptions nonceStoreOptions)
    {
        var skewSeconds = Math.Max(0, challengeOptions.ClockSkewSeconds);
        var nonceTtlSeconds = Math.Max(1, nonceStoreOptions.TtlSeconds);
        var now = DateTimeOffset.UtcNow;
        var earliestAccepted = issuedAtUtc.AddSeconds(-skewSeconds);
        var latestAccepted = issuedAtUtc.AddSeconds(nonceTtlSeconds + skewSeconds);

        return now >= earliestAccepted && now <= latestAccepted;
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
