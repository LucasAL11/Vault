using Api.Security;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

internal static class VaultAuthorization
{
    /// <summary>
    /// Autoriza acesso geral ao cofre (leitura / operações regulares de segredo).
    /// Admin Geral bypass; caso contrário, verifica membership no <c>Vault.Group</c>.
    /// </summary>
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

    /// <summary>
    /// Autoriza operações administrativas sobre um cofre específico (update / delete do cofre,
    /// CRUD de ADMaps, Machines, AutofillRules admin). Hierarquia:
    ///   1. Admin Geral (qualquer cofre)
    ///   2. Admin de Cofre: usuário em grupo AD <c>admin-vault-{Vault.TenantId}</c>
    /// Membros do <c>Vault.Group</c> sem nenhum dos dois acima NÃO podem administrar.
    /// </summary>
    public static async Task<Shared.Result<VaultAuthContext>> AuthorizeVaultAdminAsync(
        Guid vaultId,
        IMessageDispatcher sender,
        IAuthorizationService authorizationService,
        System.Security.Claims.ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var ctxResult = await sender.Send(new GetVaultAuthContextQuery(vaultId), cancellationToken);
        if (ctxResult.IsFailure)
        {
            return ctxResult;
        }

        // 1) Admin Geral: bypass total (hierarquia).
        var adminAuth = await authorizationService.AuthorizeAsync(user, AdGroupPolicyProvider.AdminPolicyName);
        if (adminAuth.Succeeded)
        {
            return Shared.Result.Success(ctxResult.Value);
        }

        // 2) Admin de Cofre: grupo AD admin-vault-{TenantId}.
        if (user.IsVaultAdminOf(ctxResult.Value.TenantId))
        {
            return Shared.Result.Success(ctxResult.Value);
        }

        return Shared.Result.Failure<VaultAuthContext>(
            Shared.Error.Forbidden("Vault.Forbidden", "User is not allowed to administer this vault."));
    }
}
