using Api.Endpoints;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Shared;

namespace Api.Endpoints.Vault.Secret;

public sealed class GetSecretAudit : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/secrets/{name}/audit", async (
            Guid vaultId,
            string name,
            int? take,
            IMessageDispatcher sender,
            ISecretAccessAuthorizer secretAccessAuthorizer,
            IUserContext userContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            httpContext.Response.ApplyNoStoreHeaders();

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            var limitedTake = Math.Clamp(take ?? 50, 1, 200);
            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: name,
                requiredPermission: VaultPermission.Admin,
                operation: "read-audit",
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
                new GetSecretAuditEntriesQuery(vaultId, name, limitedTake),
                cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error.Type == ErrorType.NotFound)
                {
                    return SecretHttpHelpers.SecureNotFound();
                }

                return CustomResults.Problem(result);
            }

            var audit = result.Value;
            return Results.Ok(new
            {
                audit.VaultId,
                SecretName = audit.SecretName,
                audit.Take,
                Entries = audit.Entries
            });
        }).RequireAuthorization().RequireRateLimiting("SecretAuditReadPolicy");
    }
}
