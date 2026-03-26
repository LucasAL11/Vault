using Api.Endpoints.Vault.Secret;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Shared;

namespace Api.Endpoints.Vault.Secret.Versions;

public sealed class RevokeVersion : SecretStore
{
    private sealed record RevokeSecretVersionRequest(string? Reason);

    public override void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/vaults/{vaultId:guid}/secrets/{name}/versions/{version:int}/revoke", async (
            Guid vaultId,
            string name,
            int version,
            RevokeSecretVersionRequest request,
            IMessageDispatcher sender,
            ISecretAccessAuthorizer secretAccessAuthorizer,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            if (version <= 0)
            {
                return Results.BadRequest(new { message = "version must be greater than zero." });
            }

            var reason = request.Reason?.Trim();
            if (string.IsNullOrWhiteSpace(reason))
            {
                return Results.BadRequest(new { message = "reason is required." });
            }

            if (reason.Length > 500)
            {
                return Results.BadRequest(new { message = "reason cannot exceed 500 characters." });
            }

            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: name,
                requiredPermission: VaultPermission.Admin,
                operation: "revoke-version",
                user: httpContext.User,
                actor: actor,
                cancellationToken: cancellationToken);

            if (authorization.IsNotFound)
            {
                return SecureNotFound();
            }

            if (!authorization.IsGranted)
            {
                return SecureForbidden();
            }

            var result = await sender.Send(
                new RevokeSecretVersionCommand(
                    VaultId: vaultId,
                    Name: name,
                    Version: version,
                    Reason: reason,
                    Actor: actor),
                cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error.Type == ErrorType.NotFound)
                {
                    return SecureNotFound();
                }

                return CustomResults.Problem(result);
            }

            var payload = result.Value;
            logger.LogInformation(
                "Secret version revoke success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, AlreadyRevoked={AlreadyRevoked}, User={User}",
                vaultId,
                payload.Name,
                payload.Version,
                payload.AlreadyRevoked,
                actor);

            return Results.Ok(new
            {
                payload.Name,
                payload.Version,
                payload.IsRevoked,
                payload.Reason,
                payload.Actor,
                payload.AlreadyRevoked
            });
        }).RequireAuthorization().RequireRateLimiting("SecretWritePolicy");
    }
}
