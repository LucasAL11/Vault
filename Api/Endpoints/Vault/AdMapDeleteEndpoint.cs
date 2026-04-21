using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.AdMaps;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AdMapDeleteEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapDelete("/vaults/{vaultId:guid}/ad-maps/{adMapId:guid}", async (
            Guid vaultId,
            Guid adMapId,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<AdMapDeleteEndpoint> logger,
            CancellationToken cancellationToken) =>
        {
            var authResult = await VaultAuthorization.AuthorizeVaultAdminAsync(
                vaultId,
                sender,
                authorizationService,
                httpContext.User,
                cancellationToken);
            if (authResult.IsFailure)
            {
                return CustomResults.Problem(authResult);
            }

            var result = await sender.Send(new DeleteAdMapCommand(vaultId, adMapId), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            logger.LogInformation(
                "AD map removed. VaultId={VaultId}, AdMapId={AdMapId}, User={User}",
                vaultId,
                adMapId,
                userContext.Identity.ToString());

            return Results.NoContent();
        }).RequireAuthorization();
    }
}
