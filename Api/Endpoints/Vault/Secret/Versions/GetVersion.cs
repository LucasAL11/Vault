using Api.Endpoints;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Shared;

namespace Api.Endpoints.Vault.Secret.Versions;

public sealed class GetVersion : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/secrets/{name}/versions", async (
            Guid vaultId,
            string name,
            bool includeRevoked,
            int? fromVersion,
            int? toVersion,
            IMessageDispatcher sender,
            ISecretAccessAuthorizer secretAccessAuthorizer,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<GetVersion> logger,
            CancellationToken cancellationToken) =>
        {
            httpContext.Response.ApplyNoStoreHeaders();

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            if (fromVersion.HasValue && fromVersion.Value <= 0)
            {
                return Results.BadRequest(new { message = "fromVersion must be greater than zero." });
            }

            if (toVersion.HasValue && toVersion.Value <= 0)
            {
                return Results.BadRequest(new { message = "toVersion must be greater than zero." });
            }

            if (fromVersion.HasValue && toVersion.HasValue && fromVersion.Value > toVersion.Value)
            {
                return Results.BadRequest(new { message = "fromVersion cannot be greater than toVersion." });
            }

            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: name,
                requiredPermission: VaultPermission.Read,
                operation: "read-versions-metadata",
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
                new ListSecretVersionsQuery(vaultId, name, includeRevoked, fromVersion, toVersion),
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
                    Action: "SECRET_READ_VERSIONS_METADATA",
                    Actor: actor,
                    Details: $"versionsCount={metadata.Versions.Count};includeRevoked={includeRevoked};fromVersion={fromVersion?.ToString() ?? "-"};toVersion={toVersion?.ToString() ?? "-"}"),
                cancellationToken);

            if (auditResult.IsFailure)
            {
                return CustomResults.Problem(auditResult);
            }

            logger.LogInformation(
                "Secret versions metadata read success. VaultId={VaultId}, SecretName={SecretName}, VersionsCount={VersionsCount}, User={User}",
                vaultId,
                metadata.Name,
                metadata.Versions.Count,
                actor);

            return Results.Ok(new
            {
                metadata.Name,
                metadata.CurrentVersion,
                Versions = metadata.Versions
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");
    }
}
