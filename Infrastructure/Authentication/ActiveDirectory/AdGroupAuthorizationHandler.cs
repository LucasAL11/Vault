using System.DirectoryServices.AccountManagement;
using Application.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Authentication.ActiveDirectory;

public sealed class AdGroupAuthorizationHandler(
    IUserContext userContext,
    ILogger<AdGroupAuthorizationHandler> logger)
    : AuthorizationHandler<AdGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdGroupRequirement requirement)
    {
        var username = userContext.Identity.Username;
        var requiredGroup = NormalizeGroupName(requirement.GroupName);

        if (string.IsNullOrWhiteSpace(username))
        {
            logger.LogWarning("AD group authorization failed: empty username in IUserContext.");
            return Task.CompletedTask;
        }

        try
        {
            using var ad = new PrincipalContext(ContextType.Domain);
            using var user =
                UserPrincipal.FindByIdentity(ad, IdentityType.SamAccountName, username)
                ?? UserPrincipal.FindByIdentity(ad, username);
            if (user is null)
            {
                logger.LogWarning("AD group authorization failed: user not found in AD. Username={Username}", username);
                return Task.CompletedTask;
            }

            // Includes nested groups. More reliable than only IsMemberOf on a single principal lookup.
            var authorizationGroups = user.GetAuthorizationGroups()
                .OfType<GroupPrincipal>()
                .ToArray();

            var isInAuthorizationGroups = authorizationGroups.Any(g =>
                string.Equals(g.SamAccountName, requiredGroup, StringComparison.OrdinalIgnoreCase)
                || string.Equals(g.Name, requiredGroup, StringComparison.OrdinalIgnoreCase)
                || string.Equals(g.DistinguishedName, requirement.GroupName, StringComparison.OrdinalIgnoreCase));

            if (isInAuthorizationGroups)
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            using var group =
                GroupPrincipal.FindByIdentity(ad, IdentityType.SamAccountName, requiredGroup)
                ?? GroupPrincipal.FindByIdentity(ad, requiredGroup)
                ?? GroupPrincipal.FindByIdentity(ad, requirement.GroupName);

            if (group is not null && user.IsMemberOf(group))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            logger.LogWarning(
                "AD group authorization denied. Username={Username}, RequiredGroup={RequiredGroup}",
                username,
                requirement.GroupName);
        }
        catch (Exception ex)
        {
            // Fail closed if AD is unavailable or lookup errors occur.
            logger.LogWarning(
                ex,
                "AD group authorization error. Username={Username}, RequiredGroup={RequiredGroup}",
                username,
                requirement.GroupName);
        }

        return Task.CompletedTask;
    }

    private static string NormalizeGroupName(string groupName)
    {
        var trimmed = groupName.Trim();
        return trimmed.Contains('\\') ? trimmed.Split('\\').Last() : trimmed;
    }
}
