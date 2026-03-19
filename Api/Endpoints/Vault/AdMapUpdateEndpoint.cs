using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.AdMaps;
using Domain.vault;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AdMapUpdateEndpoint : IEndpoint
{
    private sealed record UpdateAdMapRequest(VaultPermission Permission, bool IsActive);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPut("/vaults/{vaultId:guid}/ad-maps/{adMapId:guid}", async (
            Guid vaultId,
            Guid adMapId,
            UpdateAdMapRequest request,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<AdMapUpdateEndpoint> logger,
            CancellationToken cancellationToken) =>
        {
            var authResult = await VaultAuthorization.AuthorizeVaultAsync(
                vaultId,
                sender,
                authorizationService,
                httpContext.User,
                cancellationToken);
            if (authResult.IsFailure)
            {
                return CustomResults.Problem(authResult);
            }

            var result = await sender.Send(
                new UpdateAdMapCommand(vaultId, adMapId, request.Permission, request.IsActive),
                cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            logger.LogInformation(
                "AD map updated. VaultId={VaultId}, AdMapId={AdMapId}, Permission={Permission}, IsActive={IsActive}, User={User}",
                vaultId,
                adMapId,
                result.Value.Permission,
                result.Value.IsActive,
                userContext.Identity.ToString());

            return Results.Ok(result.Value);
        }).RequireAuthorization();
    }
}
