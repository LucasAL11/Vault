using Application.Abstractions.Messaging.Handlers;
using Application.Vault;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

internal static class VaultAuthorization
{
    public static async Task<Shared.Result<string>> AuthorizeVaultAsync(
        Guid vaultId,
        IMessageDispatcher sender,
        IAuthorizationService authorizationService,
        System.Security.Claims.ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var vaultGroup = await sender.Send(new GetVaultGroupQuery(vaultId), cancellationToken);
        if (vaultGroup.IsFailure)
        {
            return vaultGroup;
        }

        // Admins can access any vault
        var adminAuth = await authorizationService.AuthorizeAsync(user, AdGroupPolicyProvider.AdminPolicyName);
        if (adminAuth.Succeeded)
        {
            return Shared.Result.Success(vaultGroup.Value);
        }

        // Non-admins: check vault-specific group
        var policy = $"AdGroup:{vaultGroup.Value}";
        var authorization = await authorizationService.AuthorizeAsync(user, policy);
        return authorization.Succeeded
            ? Shared.Result.Success(vaultGroup.Value)
            : Shared.Result.Failure<string>(
                Shared.Error.Forbidden("Vault.Forbidden", "User is not allowed for this vault."));
    }
}
