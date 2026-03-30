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
    private const string DummyClientId = "__challenge-invalid-client__";
    private const string DummySubject = "__challenge-invalid-subject__";
    private const int MaxClientIdLength = 80;
    private const int MaxUserNameLength = 128;
    private const int MaxDomainLength = 128;
    private const int MaxNonceEncodedLength = 128;
    private const int MaxSignatureEncodedLength = 128;
    private const int ExpectedNonceByteLength = 32;
    private const int ExpectedSignatureByteLength = 32;
    private static readonly byte[] DummyNonceBytes = new byte[32];
    private static readonly string EphemeralFallbackSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

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

            var options = challengeOptions.Value;
            if (string.IsNullOrWhiteSpace(request.ClientId) ||
                string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.Domain) ||
                string.IsNullOrWhiteSpace(request.Nonce) ||
                string.IsNullOrWhiteSpace(request.Signature))
            {
                return Results.BadRequest(new { message = "clientId, username, domain, nonce and signature are required." });
            }

            if (!InputValidation.TryNormalizeAsciiToken(request.ClientId, minLength: 1, maxLength: MaxClientIdLength, allowedSymbols: "._:-", out var normalizedClientId))
            {
                return Results.BadRequest(new { message = "clientId is invalid." });
            }

            if (!InputValidation.TryNormalizeAsciiToken(request.Username, minLength: 1, maxLength: MaxUserNameLength, allowedSymbols: "._-@", out var normalizedUsername))
            {
                return Results.BadRequest(new { message = "username is invalid." });
            }

            if (!InputValidation.TryNormalizeAsciiToken(request.Domain, minLength: 1, maxLength: MaxDomainLength, allowedSymbols: "._-", out var normalizedDomain))
            {
                return Results.BadRequest(new { message = "domain is invalid." });
            }

            if (request.IssuedAtUtc == default)
            {
                return Results.BadRequest(new { message = "issuedAtUtc is required." });
            }

            var hasClientSecret = TryGetClientSecret(normalizedClientId, options, out var configuredClientSecret);
            var effectiveClientSecret = hasClientSecret
                ? configuredClientSecret
                : ResolveFallbackSecret(options);

            var nonceParsed = InputValidation.TryDecodeBase64Url(
                request.Nonce,
                minByteLength: ExpectedNonceByteLength,
                maxByteLength: ExpectedNonceByteLength,
                maxEncodedLength: MaxNonceEncodedLength,
                out var normalizedNonce,
                out var nonceBytes);
            var effectiveNonceBytes = nonceParsed ? nonceBytes : DummyNonceBytes;

            var signaturePayload = BuildSignedPayload(
                normalizedClientId,
                normalizedUsername,
                normalizedDomain,
                normalizedNonce,
                request.IssuedAtUtc);

            var signatureParsed = InputValidation.TryDecodeBase64Url(
                request.Signature,
                minByteLength: ExpectedSignatureByteLength,
                maxByteLength: ExpectedSignatureByteLength,
                maxEncodedLength: MaxSignatureEncodedLength,
                out _,
                out var providedSignature);

            var signatureValid = IsSignatureValid(signaturePayload, providedSignature, signatureParsed, effectiveClientSecret);
            var withinSkewWindow = IsWithinSkewWindow(
                request.IssuedAtUtc,
                options,
                nonceStoreOptions.Value);
            var nonceAudience = NonceChallengeAudiences.AuthChallengeRespond;
            var subject = NonceChallengeScope.BuildCredentialSubject(normalizedDomain, normalizedUsername);

            var shouldConsumeIssuedNonce = hasClientSecret && nonceParsed && signatureValid && withinSkewWindow;
            var consumeScope = shouldConsumeIssuedNonce
                ? NonceChallengeScope.Build(httpContext, normalizedClientId, subject, nonceAudience)
                : NonceChallengeScope.Build(httpContext, DummyClientId, DummySubject, nonceAudience);
            var consumeNonceBytes = shouldConsumeIssuedNonce ? effectiveNonceBytes : DummyNonceBytes;
            var consumed = await nonceStore.TryConsumeAsync(consumeScope, consumeNonceBytes, cancellationToken);

            var authSucceeded = hasClientSecret && nonceParsed && signatureValid && withinSkewWindow && consumed;
            if (!authSucceeded)
            {
                return Results.Unauthorized();
            }

            var loginResult = Domain.Users.Login.Create(normalizedUsername);
            if (loginResult.IsFailure)
            {
                return Results.BadRequest(new { message = "username is invalid." });
            }

            var token = tokenProvider.Create(loginResult.Value);
            return Results.Ok(new
            {
                accessToken = token,
                tokenType = "Bearer",
                username = normalizedUsername,
                domain = normalizedDomain
            });
        }).AllowAnonymous().RequireRateLimiting("AuthChallengeRespondPolicy");
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

    private static string ResolveFallbackSecret(AuthChallengeOptions options)
    {
        foreach (var entry in options.ClientSecrets)
        {
            if (!string.IsNullOrWhiteSpace(entry.Value))
            {
                return entry.Value;
            }
        }

        return EphemeralFallbackSecret;
    }

    private static bool IsSignatureValid(
        string payload,
        ReadOnlySpan<byte> providedSignature,
        bool signatureParsed,
        string clientSecret)
    {
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        using var hmac = new HMACSHA256(secretBytes);
        var expectedSignature = hmac.ComputeHash(payloadBytes);

        var signaturesMatch = FixedTimeEqualsWithExpectedLength(providedSignature, expectedSignature, expectedSignature.Length);
        return signatureParsed & signaturesMatch;
    }

    private static bool FixedTimeEqualsWithExpectedLength(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, int expectedLength)
    {
        Span<byte> leftBuffer = stackalloc byte[expectedLength];
        Span<byte> rightBuffer = stackalloc byte[expectedLength];
        leftBuffer.Clear();
        rightBuffer.Clear();

        var leftCopy = Math.Min(left.Length, expectedLength);
        var rightCopy = Math.Min(right.Length, expectedLength);
        left[..leftCopy].CopyTo(leftBuffer);
        right[..rightCopy].CopyTo(rightBuffer);

        var bytesEqual = CryptographicOperations.FixedTimeEquals(leftBuffer, rightBuffer);
        var lengthsEqual = left.Length == expectedLength && right.Length == expectedLength;
        return bytesEqual & lengthsEqual;
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

    private static void ApplyNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }
}
