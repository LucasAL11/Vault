using Application.Abstractions.Messaging.Handlers;
using Application.Vault.Secrets;
using Domain.vault;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;
using Shared;

namespace Api.Endpoints.Vault.Secret;

internal interface ISecretAccessAuthorizer
{
    Task<SecretAccessDecision> AuthorizeAsync(
        Guid vaultId,
        string secretName,
        VaultPermission requiredPermission,
        string operation,
        System.Security.Claims.ClaimsPrincipal user,
        string actor,
        CancellationToken cancellationToken);
}

internal readonly record struct SecretAccessDecision(bool IsGranted, bool IsNotFound)
{
    public static SecretAccessDecision Granted => new(true, false);
    public static SecretAccessDecision Forbidden => new(false, false);
    public static SecretAccessDecision NotFound => new(false, true);
}

internal sealed class SecretAccessAuthorizer(
    IMessageDispatcher sender,
    IAuthorizationService authorizationService,
    ILogger<SecretAccessAuthorizer> logger) : ISecretAccessAuthorizer
{
    public async Task<SecretAccessDecision> AuthorizeAsync(
        Guid vaultId,
        string secretName,
        VaultPermission requiredPermission,
        string operation,
        System.Security.Claims.ClaimsPrincipal user,
        string actor,
        CancellationToken cancellationToken)
    {
        var contextResult = await sender.Send(
            new GetSecretAuthorizationContextQuery(vaultId, requiredPermission),
            cancellationToken);

        if (contextResult.IsFailure)
        {
            if (contextResult.Error.Type == ErrorType.NotFound)
            {
                logger.LogWarning(
                    "Secret {Operation} denied: vault not found. VaultId={VaultId}, User={User}",
                    operation,
                    vaultId,
                    actor);
                return SecretAccessDecision.NotFound;
            }

            logger.LogWarning(
                "Secret {Operation} denied: failed to load authorization context. VaultId={VaultId}, ErrorCode={ErrorCode}, User={User}",
                operation,
                vaultId,
                contextResult.Error.Code,
                actor);
            return SecretAccessDecision.Forbidden;
        }

        var context = contextResult.Value;
        if (context.VaultStatus != Status.Active)
        {
            await AppendAuditBestEffortAsync(
                action: "SECRET_ACCESS_DENIED",
                actor: actor,
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=vault-status-not-active;vaultStatus={context.VaultStatus}",
                cancellationToken: cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: vault status is not active. VaultId={VaultId}, VaultStatus={VaultStatus}, User={User}",
                operation,
                vaultId,
                context.VaultStatus,
                actor);
            return SecretAccessDecision.Forbidden;
        }

        // Admins bypass ADMap checks
        var adminAuth = await authorizationService.AuthorizeAsync(user, AdGroupPolicyProvider.AdminPolicyName);
        if (adminAuth.Succeeded)
        {
            await AppendAuditBestEffortAsync(
                action: "SECRET_ACCESS_GRANTED",
                actor: actor,
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};requiredPermission={requiredPermission};grant=admin-policy",
                cancellationToken: cancellationToken);
            return SecretAccessDecision.Granted;
        }

        if (string.IsNullOrWhiteSpace(context.VaultGroup))
        {
            await AppendAuditBestEffortAsync(
                action: "SECRET_ACCESS_DENIED",
                actor: actor,
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=vault-without-group-policy",
                cancellationToken: cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: vault without group policy. VaultId={VaultId}, User={User}",
                operation,
                vaultId,
                actor);
            return SecretAccessDecision.Forbidden;
        }

        var vaultPolicy = $"AdGroup:{context.VaultGroup}";
        var vaultResult = await authorizationService.AuthorizeAsync(user, vaultPolicy);
        if (!vaultResult.Succeeded)
        {
            await AppendAuditBestEffortAsync(
                action: "SECRET_ACCESS_DENIED",
                actor: actor,
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=vault-group-policy-failed;vaultGroup={context.VaultGroup}",
                cancellationToken: cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: vault group authorization failed. VaultId={VaultId}, VaultGroup={VaultGroup}, User={User}",
                operation,
                vaultId,
                context.VaultGroup,
                actor);
            return SecretAccessDecision.Forbidden;
        }

        if (context.CandidateGroups.Count == 0)
        {
            await AppendAuditBestEffortAsync(
                action: "SECRET_ACCESS_DENIED",
                actor: actor,
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=no-active-admap;requiredPermission={requiredPermission}",
                cancellationToken: cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: no active ADMap with required permission. VaultId={VaultId}, RequiredPermission={RequiredPermission}, User={User}",
                operation,
                vaultId,
                requiredPermission,
                actor);
            return SecretAccessDecision.Forbidden;
        }

        // Keep sequential checks to avoid burst traffic against remote
        // authorization backends when many groups are mapped.
        foreach (var groupId in context.CandidateGroups)
        {
            var adMapPolicy = $"AdGroup:{groupId}";
            var adMapResult = await authorizationService.AuthorizeAsync(user, adMapPolicy);
            if (adMapResult.Succeeded)
            {
                await AppendAuditBestEffortAsync(
                    action: "SECRET_ACCESS_GRANTED",
                    actor: actor,
                    vaultId: vaultId,
                    secretName: secretName,
                    details: $"operation={operation};requiredPermission={requiredPermission};group={groupId}",
                    cancellationToken: cancellationToken);

                return SecretAccessDecision.Granted;
            }
        }

        await AppendAuditBestEffortAsync(
            action: "SECRET_ACCESS_DENIED",
            actor: actor,
            vaultId: vaultId,
            secretName: secretName,
            details: $"operation={operation};reason=admap-policy-failed;requiredPermission={requiredPermission};candidateGroups={string.Join(",", context.CandidateGroups)}",
            cancellationToken: cancellationToken);

        logger.LogWarning(
            "Secret {Operation} denied: user is not authorized by ADMap. VaultId={VaultId}, RequiredPermission={RequiredPermission}, CandidateGroups={CandidateGroups}, User={User}",
            operation,
            vaultId,
            requiredPermission,
            context.CandidateGroups,
            actor);

        return SecretAccessDecision.Forbidden;
    }

    private async Task AppendAuditBestEffortAsync(
        string action,
        string actor,
        Guid? vaultId,
        string? secretName,
        string? details,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await sender.Send(
                new AppendSecretAuditCommand(
                    VaultId: vaultId,
                    SecretName: secretName,
                    Action: action,
                    Actor: actor,
                    Details: details),
                cancellationToken);

            if (result.IsFailure)
            {
                logger.LogError(
                    "Failed to persist authorization audit entry. Action={Action}, VaultId={VaultId}, SecretName={SecretName}, ErrorCode={ErrorCode}",
                    action,
                    vaultId,
                    secretName,
                    result.Error.Code);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Failed to persist authorization audit entry. Action={Action}, VaultId={VaultId}, SecretName={SecretName}",
                action,
                vaultId,
                secretName);
        }
    }
}
