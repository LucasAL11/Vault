using Api.Infrastructure;
using Api.Security;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Shared;

namespace Api.Endpoints.Vault.Secret;

public sealed class PutSecret : SecretStore
{
    private sealed record UpsertRequest(string Value, string? ContentType, DateTimeOffset? ExpiresUtc);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPut("/vaults/{vaultId:guid}/secrets/{name}", async (
            Guid vaultId,
            string name,
            UpsertRequest request,
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

            if (string.IsNullOrWhiteSpace(request.Value))
            {
                return Results.BadRequest(new { message = "Secret value is required." });
            }

            if (!InputValidation.TryNormalizeText(
                    request.ContentType,
                    minLength: 1,
                    maxLength: MaxContentTypeLength,
                    out var normalizedContentType))
            {
                normalizedContentType = "text/plain";
            }

            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: name,
                requiredPermission: VaultPermission.Write,
                operation: "write",
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
                new UpsertSecretCommand(
                    VaultId: vaultId,
                    Name: name,
                    Value: request.Value,
                    ContentType: normalizedContentType,
                    ExpiresUtc: request.ExpiresUtc,
                    Actor: actor),
                cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error.Type == ErrorType.NotFound)
                {
                    return SecureNotFound();
                }

                if (result.Error.Type == ErrorType.BadRequest)
                {
                    return Results.BadRequest(new { message = result.Error.Description });
                }

                return CustomResults.Problem(result);
            }

            var upsert = result.Value;
            logger.LogInformation(
                "Secret write success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, KeyReference={KeyReference}, User={User}",
                vaultId,
                upsert.Name,
                upsert.Version,
                upsert.KeyReference,
                actor);

            return Results.Ok(new
            {
                upsert.Id,
                upsert.Name,
                upsert.Version,
                upsert.KeyReference,
                upsert.Expires
            });
        }).RequireAuthorization().RequireRateLimiting("SecretWritePolicy");
    }
}
