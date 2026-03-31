using System.Security.Claims;
using Application.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Authentication.ActiveDirectory;

/// <summary>
/// Handles <see cref="AdminGroupRequirement"/> by checking if the user belongs to
/// ANY of the configured admin groups (from appsettings Authorization:AdminGroups).
/// Delegates to the same claim-checking logic as AdGroupAuthorizationHandler.
/// </summary>
public sealed class AdminGroupAuthorizationHandler(
    IUserContext userContext,
    ILogger<AdminGroupAuthorizationHandler> logger)
    : AuthorizationHandler<AdminGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdminGroupRequirement requirement)
    {
        foreach (var adminGroup in requirement.AdminGroups)
        {
            var normalizedGroup = NormalizeGroupName(adminGroup);

            // Check JWT claims (role, groups)
            if (IsInGroupClaims(context.User, normalizedGroup, adminGroup))
            {
                logger.LogInformation(
                    "Admin authorization succeeded source=claims username={Username} matchedGroup={MatchedGroup}",
                    userContext.Identity.Username,
                    adminGroup);
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Check server-side groups (IUserContext)
            if (IsInUserContextGroups(userContext.Groups, normalizedGroup, adminGroup))
            {
                logger.LogInformation(
                    "Admin authorization succeeded source=user_context username={Username} matchedGroup={MatchedGroup}",
                    userContext.Identity.Username,
                    adminGroup);
                context.Succeed(requirement);
                return Task.CompletedTask;
            }
        }

        logger.LogWarning(
            "Admin authorization denied username={Username} requiredGroups=[{RequiredGroups}]",
            userContext.Identity.Username,
            string.Join(", ", requirement.AdminGroups));

        return Task.CompletedTask;
    }

    private static bool IsInGroupClaims(ClaimsPrincipal user, string normalizedGroup, string fullGroup)
    {
        foreach (var claim in user.Claims)
        {
            if (claim.Type != ClaimTypes.Role &&
                !string.Equals(claim.Type, "role", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(claim.Type, "groups", StringComparison.OrdinalIgnoreCase))
                continue;

            var claimValue = claim.Value?.Trim();
            if (string.IsNullOrWhiteSpace(claimValue))
                continue;

            var normalizedClaim = NormalizeGroupName(claimValue);
            if (string.Equals(normalizedClaim, normalizedGroup, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(claimValue, fullGroup, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool IsInUserContextGroups(
        IReadOnlySet<Domain.Users.UserGroup> groups, string normalizedGroup, string fullGroup)
    {
        foreach (var group in groups)
        {
            var name = group.Name?.Trim();
            if (string.IsNullOrWhiteSpace(name))
                continue;

            var normalized = NormalizeGroupName(name);
            if (string.Equals(normalized, normalizedGroup, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, fullGroup, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string NormalizeGroupName(string groupName)
    {
        var trimmed = groupName.Trim();
        return trimmed.Contains('\\') ? trimmed.Split('\\').Last() : trimmed;
    }
}
