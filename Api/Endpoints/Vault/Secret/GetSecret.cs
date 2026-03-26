using Api.Endpoints;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Shared;

namespace Api.Endpoints.Vault.Secret;

public sealed class GetSecret : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/secrets/{name}", async (
            Guid vaultId,
            string name,
            IMessageDispatcher sender,
            ISecretAccessAuthorizer secretAccessAuthorizer,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<GetSecret> logger,
            CancellationToken cancellationToken) =>
        {
            httpContext.Response.ApplyNoStoreHeaders();

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: name,
                requiredPermission: VaultPermission.Read,
                operation: "read-metadata",
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

            var result = await sender.Send(
                new GetSecretMetadataQuery(vaultId, name),
                cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error.Type == ErrorType.NotFound)
                {
                    return SecretHttpHelpers.SecureNotFound();
                }

                return CustomResults.Problem(result);
            }

            var metadata = result.Value;
            var auditResult = await sender.Send(
                new AppendSecretAuditCommand(
                    VaultId: vaultId,
                    SecretName: metadata.Name,
                    Action: "SECRET_READ_METADATA",
                    Actor: actor,
                    Details: $"version={metadata.Version};keyId={metadata.KeyReference};revoked={metadata.IsRevoked}"),
                cancellationToken);

            if (auditResult.IsFailure)
            {
                return CustomResults.Problem(auditResult);
            }

            logger.LogInformation(
                "Secret metadata read success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, User={User}",
                vaultId,
                metadata.Name,
                metadata.Version,
                actor);

            return Results.Ok(new
            {
                metadata.Name,
                metadata.Version,
                metadata.ContentType,
                metadata.KeyReference,
                metadata.IsRevoked,
                metadata.Expires
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");
    }
}
