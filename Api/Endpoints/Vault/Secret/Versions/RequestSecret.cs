using Api.Endpoints;
using Api.Endpoints.Users;
using Api.Infrastructure;
using Api.Security;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Security;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Infrastructure.Security;
using Microsoft.Extensions.Options;
using Shared;

namespace Api.Endpoints.Vault.Secret.Versions;

public sealed class RequestSecret : IEndpoint
{
    private const string ContractVersion = "v1";
    private const string DummyClientId = "__vault-proof-invalid-client__";
    private const string DummySubject = "__vault-proof-invalid-subject__";
    private static readonly byte[] DummyNonceBytes = new byte[32];
    private const int MaxReasonLength = 500;
    private const int MaxTicketLength = 512;
    private const int MaxClientIdLength = 256;
    private const int ExpectedNonceByteLength = 32;
    private const int MaxNonceEncodedLength = 48;
    private const int ExpectedProofByteLength = 32;
    private const int MaxProofEncodedLength = 48;

    private sealed class SecretRequestPayload
    {
        public string? ContractVersion { get; init; }
        public string? Reason { get; init; }
        public string? Ticket { get; init; }
        public string? TicketId { get; init; }
        public string? ClientId { get; init; }
        public string? Nonce { get; init; }
        public DateTimeOffset? IssuedAt { get; init; }
        public DateTimeOffset? IssuedAtUtc { get; init; }
        public string? Proof { get; init; }
    }

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/vaults/{vaultId:guid}/secrets/{name}/request", async (
            Guid vaultId,
            string name,
            SecretRequestPayload request,
            IMessageDispatcher sender,
            ISecretAccessAuthorizer secretAccessAuthorizer,
            IUserContext userContext,
            INonceStore nonceStore,
            IOptions<AuthChallengeOptions> challengeOptions,
            IOptions<NonceStoreOptions> nonceStoreOptions,
            HttpContext httpContext,
            ILogger<RequestSecret> logger,
            CancellationToken cancellationToken) =>
        {
            httpContext.Response.ApplyNoStoreHeaders();

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            if (!InputValidation.TryNormalizeAsciiToken(
                    request.ContractVersion,
                    minLength: 1,
                    maxLength: 16,
                    allowedSymbols: "._-",
                    out var contractVersion) ||
                !string.Equals(contractVersion, ContractVersion, StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest(new
                {
                    message = $"contractVersion is invalid. Supported value: {ContractVersion}."
                });
            }

            if (!InputValidation.TryNormalizeText(request.Reason, minLength: 1, maxLength: MaxReasonLength, out var normalizedReason) ||
                normalizedReason.Contains('|'))
            {
                return Results.BadRequest(new { message = "reason is invalid." });
            }

            var ticket = SecretProofHelpers.ResolveTicket(request.Ticket, request.TicketId);
            if (!InputValidation.TryNormalizeText(ticket, minLength: 1, maxLength: MaxTicketLength, out var normalizedTicket) ||
                normalizedTicket.Contains('|'))
            {
                return Results.BadRequest(new { message = "ticket is invalid." });
            }

            if (!InputValidation.TryNormalizeAsciiToken(request.ClientId, minLength: 1, maxLength: MaxClientIdLength, allowedSymbols: "._:-", out var normalizedClientId))
            {
                return Results.BadRequest(new { message = "clientId is invalid." });
            }

            var issuedAt = request.IssuedAt ?? request.IssuedAtUtc;
            if (!issuedAt.HasValue || issuedAt.Value == default)
            {
                return Results.BadRequest(new { message = "issuedAt is required." });
            }

            var normalizedIssuedAt = issuedAt.Value;
            if (string.IsNullOrWhiteSpace(request.Nonce) || string.IsNullOrWhiteSpace(request.Proof))
            {
                return Results.BadRequest(new
                {
                    message = "Required contract fields: reason, ticket, clientId, nonce, issuedAt, proof."
                });
            }

            var nonceParsed = InputValidation.TryDecodeBase64Url(
                request.Nonce,
                minByteLength: ExpectedNonceByteLength,
                maxByteLength: ExpectedNonceByteLength,
                maxEncodedLength: MaxNonceEncodedLength,
                out var normalizedNonce,
                out var nonceBytes);

            var signatureParsed = InputValidation.TryDecodeBase64Url(
                request.Proof,
                minByteLength: ExpectedProofByteLength,
                maxByteLength: ExpectedProofByteLength,
                maxEncodedLength: MaxProofEncodedLength,
                out _,
                out var providedSignature);

            // Intentionally keep the control flow close to the valid path to reduce
            // timing side-channel signal for malformed nonce/proof payloads.
            if (!nonceParsed || !signatureParsed)
            {
                logger.LogWarning(
                    "Secret request denied: malformed nonce/proof payload. VaultId={VaultId}, SecretName={SecretName}, User={User}",
                    vaultId,
                    name,
                    userContext.Identity.ToString());
            }

            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: name,
                requiredPermission: VaultPermission.Read,
                operation: "request-value",
                user: httpContext.User,
                actor: actor,
                cancellationToken: cancellationToken);

            if (authorization.IsNotFound)
            {
                return SecretHttpHelpers.SecureNotFound();
            }

            if (!authorization.IsGranted)
            {
                return SecretHttpHelpers.SecureForbidden();
            }

            if (!NonceChallengeScope.TryResolveSubject(httpContext, requestedSubject: null, out var subject))
            {
                logger.LogWarning(
                    "Secret request denied: unable to resolve subject. VaultId={VaultId}, SecretName={SecretName}, User={User}",
                    vaultId,
                    name,
                    actor);
                return Results.Unauthorized();
            }

            var authChallengeOptions = challengeOptions.Value;
            var nonceOptions = nonceStoreOptions.Value;
            var hasClientSecret = SecretProofHelpers.TryGetClientSecret(normalizedClientId, authChallengeOptions, out var configuredClientSecret);
            var effectiveClientSecret = hasClientSecret
                ? configuredClientSecret
                : SecretProofHelpers.ResolveFallbackSecret(authChallengeOptions);
            var effectiveNonceBytes = nonceParsed ? nonceBytes : DummyNonceBytes;
            var proofPayload = SecretProofHelpers.BuildProofPayload(
                vaultId,
                name,
                normalizedClientId,
                subject,
                normalizedReason,
                normalizedTicket,
                normalizedNonce,
                normalizedIssuedAt);
            var signatureValid = SecretProofHelpers.IsSignatureValid(proofPayload, providedSignature, signatureParsed, effectiveClientSecret);
            var withinSkewWindow = SecretProofHelpers.IsWithinSkewWindow(normalizedIssuedAt, authChallengeOptions, nonceOptions);

            var shouldConsumeIssuedNonce = hasClientSecret && nonceParsed && signatureValid && withinSkewWindow;
            var consumeScope = shouldConsumeIssuedNonce
                ? NonceChallengeScope.Build(
                    httpContext,
                    normalizedClientId,
                    subject,
                    NonceChallengeAudiences.VaultSecretRequest)
                : NonceChallengeScope.Build(
                    httpContext,
                    DummyClientId,
                    DummySubject,
                    NonceChallengeAudiences.VaultSecretRequest);
            var consumeNonceBytes = shouldConsumeIssuedNonce ? effectiveNonceBytes : DummyNonceBytes;
            var nonceConsumed = await nonceStore.TryConsumeAsync(consumeScope, consumeNonceBytes, cancellationToken);

            var proofValid = hasClientSecret && nonceParsed && signatureValid && withinSkewWindow && nonceConsumed;
            if (!proofValid)
            {
                // DEBUG: log every flag and the exact payload so we can compare with the extension
                logger.LogWarning(
                    "Secret request PROOF DEBUG: " +
                    "hasClientSecret={HasClientSecret}, nonceParsed={NonceParsed}, " +
                    "signatureValid={SignatureValid}, withinSkewWindow={WithinSkewWindow}, " +
                    "nonceConsumed={NonceConsumed}, " +
                    "subject={Subject}, payload={Payload}, " +
                    "clientId={ClientId}, reason={Reason}, ticket={Ticket}, " +
                    "nonce={Nonce}, issuedAtUtc={IssuedAtUtc}",
                    hasClientSecret, nonceParsed,
                    signatureValid, withinSkewWindow,
                    nonceConsumed,
                    subject, proofPayload,
                    normalizedClientId, normalizedReason, normalizedTicket,
                    normalizedNonce, normalizedIssuedAt.ToString("O"));

                var deniedAuditResult = await sender.Send(
                    new AppendSecretAuditCommand(
                        VaultId: vaultId,
                        SecretName: name,
                        Action: "SECRET_REQUEST_VALUE_DENIED",
                        Actor: actor,
                        Details: $"reason=invalid-proof;clientId={normalizedClientId}"),
                    cancellationToken);

                if (deniedAuditResult.IsFailure)
                {
                    return CustomResults.Problem(deniedAuditResult);
                }

                logger.LogWarning(
                    "Secret request denied: proof validation failed. VaultId={VaultId}, SecretName={SecretName}, User={User}",
                    vaultId,
                    name,
                    actor);
                return Results.Unauthorized();
            }

            var result = await sender.Send(
                new RequestSecretValueQuery(vaultId, name),
                cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error.Type == ErrorType.NotFound)
                {
                    return SecretHttpHelpers.SecureNotFound();
                }

                return CustomResults.Problem(result);
            }

            var requestedSecret = result.Value;
            var successAuditResult = await sender.Send(
                new AppendSecretAuditCommand(
                    VaultId: vaultId,
                    SecretName: requestedSecret.Name,
                    Action: "SECRET_REQUEST_VALUE",
                    Actor: actor,
                    Details: $"version={requestedSecret.Version};ticket={SecretProofHelpers.NormalizeTicketId(normalizedTicket)};reason={normalizedReason};clientId={normalizedClientId};contractVersion={ContractVersion}"),
                cancellationToken);

            if (successAuditResult.IsFailure)
            {
                return CustomResults.Problem(successAuditResult);
            }

            logger.LogInformation(
                "Secret request success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, User={User}",
                vaultId,
                requestedSecret.Name,
                requestedSecret.Version,
                actor);

            return Results.Ok(new
            {
                requestedSecret.Name,
                requestedSecret.Version,
                requestedSecret.ContentType,
                Value = requestedSecret.Value,
                requestedSecret.Expires
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");
    }
}
