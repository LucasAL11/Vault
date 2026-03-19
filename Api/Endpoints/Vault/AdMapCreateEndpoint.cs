using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.AdMaps.create;
using Domain.vault;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AdMapCreateEndpoint : IEndpoint
{
    private sealed record CreateAdMapRequest(string GroupId, VaultPermission Permission, bool IsActive = true);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/vaults/{vaultId:guid}/ad-maps", async (
                Guid vaultId,
                CreateAdMapRequest request,
                IMessageDispatcher sender,
                IAuthorizationService authorizationService,
                IUserContext userContext,
                HttpContext httpContext,
                ILogger<AdMapCreateEndpoint> logger,
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
                    new CreateAdMapCommand(vaultId, request.GroupId, request.Permission, request.IsActive),
                    cancellationToken);
                if (result.IsFailure)
                {
                    return CustomResults.Problem(result);
                }

                logger.LogInformation(
                    "AD map created. VaultId={VaultId}, AdMapId={AdMapId}, GroupId={GroupId}, Permission={Permission}, User={User}",
                    vaultId,
                    result.Value.Id,
                    result.Value.GroupId,
                    result.Value.Permission,
                    userContext.Identity.ToString());

                return Results.Created($"/vaults/{vaultId}/ad-maps/{result.Value.Id}", result.Value);
            }).RequireAuthorization()
            .WithTags("active-directory");
    }
}
