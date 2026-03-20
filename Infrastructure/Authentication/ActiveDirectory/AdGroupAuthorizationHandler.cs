using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using Application.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Authentication.ActiveDirectory;

public sealed class AdGroupAuthorizationHandler(
    IUserContext userContext,
    IOptions<ActiveDirectoryOptions> adOptions,
    ILogger<AdGroupAuthorizationHandler> logger)
    : AuthorizationHandler<AdGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdGroupRequirement requirement)
    {
        var requiredGroup = NormalizeGroupName(requirement.GroupName);
        var requiredFullGroup = requirement.GroupName.Trim();

        if (IsInGroupClaims(context.User, requiredGroup, requiredFullGroup))
        {
            logger.LogInformation(
                "AD authorization succeeded source={Source} username={Username} requiredGroup={RequiredGroup}",
                "claims",
                userContext.Identity.Username,
                requirement.GroupName);
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (IsInUserContextGroups(userContext.Groups, requiredGroup, requiredFullGroup))
        {
            logger.LogInformation(
                "AD authorization succeeded source={Source} username={Username} requiredGroup={RequiredGroup}",
                "user_context",
                userContext.Identity.Username,
                requirement.GroupName);
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var tokenOverageDetected = IsTokenOverageDetected(context.User);
        if (tokenOverageDetected)
        {
            logger.LogInformation(
                "Token group overage detected. Falling back to server-side group resolution. RequiredGroup={RequiredGroup}",
                requirement.GroupName);
        }

        if (!adOptions.Value.Enabled)
        {
            logger.LogWarning(
                "AD group authorization denied: LDAP/AD lookup is disabled. RequiredGroup={RequiredGroup}",
                requirement.GroupName);
            return Task.CompletedTask;
        }

        var username = userContext.Identity.Username;

        if (string.IsNullOrWhiteSpace(username))
        {
            logger.LogWarning("AD group authorization failed: empty username in IUserContext.");
            return Task.CompletedTask;
        }

        try
        {
            using var ad = BuildPrincipalContext(adOptions.Value);
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
                logger.LogInformation(
                    "AD authorization succeeded source={Source} username={Username} requiredGroup={RequiredGroup}",
                    "ad_lookup_groups",
                    username,
                    requirement.GroupName);
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            using var group =
                GroupPrincipal.FindByIdentity(ad, IdentityType.SamAccountName, requiredGroup)
                ?? GroupPrincipal.FindByIdentity(ad, requiredGroup)
                ?? GroupPrincipal.FindByIdentity(ad, requirement.GroupName);

            if (group is not null && user.IsMemberOf(group))
            {
                logger.LogInformation(
                    "AD authorization succeeded source={Source} username={Username} requiredGroup={RequiredGroup}",
                    "ad_lookup_membership",
                    username,
                    requirement.GroupName);
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            logger.LogInformation(
                "AD authorization denied source={Source} username={Username} requiredGroup={RequiredGroup} tokenOverage={TokenOverage}",
                "ad_lookup",
                username,
                requirement.GroupName,
                tokenOverageDetected);
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

    private static PrincipalContext BuildPrincipalContext(ActiveDirectoryOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.Domain) && !string.IsNullOrWhiteSpace(options.Container))
        {
            return new PrincipalContext(ContextType.Domain, options.Domain, options.Container);
        }

        if (!string.IsNullOrWhiteSpace(options.Domain))
        {
            return new PrincipalContext(ContextType.Domain, options.Domain);
        }

        return new PrincipalContext(ContextType.Domain);
    }

    private static bool IsInGroupClaims(ClaimsPrincipal user, string requiredGroup, string requiredFullGroup)
    {
        foreach (var claim in user.Claims)
        {
            if (claim.Type != ClaimTypes.Role &&
                !string.Equals(claim.Type, "role", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(claim.Type, "groups", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var claimValue = claim.Value?.Trim();
            if (string.IsNullOrWhiteSpace(claimValue))
            {
                continue;
            }

            var normalizedClaim = NormalizeGroupName(claimValue);
            if (string.Equals(normalizedClaim, requiredGroup, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(claimValue, requiredFullGroup, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsInUserContextGroups(IReadOnlySet<Domain.Users.UserGroup> groups, string requiredGroup, string requiredFullGroup)
    {
        foreach (var group in groups)
        {
            var name = group.Name?.Trim();
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var normalized = NormalizeGroupName(name);
            if (string.Equals(normalized, requiredGroup, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, requiredFullGroup, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsTokenOverageDetected(ClaimsPrincipal user)
    {
        foreach (var claim in user.Claims)
        {
            if (string.Equals(claim.Type, "hasgroups", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(claim.Value, "true", StringComparison.OrdinalIgnoreCase) || claim.Value == "1"))
            {
                return true;
            }

            if (string.Equals(claim.Type, "_claim_names", StringComparison.OrdinalIgnoreCase) &&
                claim.Value.Contains("groups", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(claim.Type, "http://schemas.microsoft.com/claims/groups.link", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string NormalizeGroupName(string groupName)
    {
        var trimmed = groupName.Trim();
        return trimmed.Contains('\\') ? trimmed.Split('\\').Last() : trimmed;
    }
}
