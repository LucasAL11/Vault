using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using Application.Authentication;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;

namespace Infrastructure.Authentication;

public sealed class AdGroupAuthorizationHandler(IUserContext userContext) : AuthorizationHandler<AdGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdGroupRequirement requirement)
    {
        var username = userContext.Identity.Username;

        if (string.IsNullOrWhiteSpace(username))
        {
            return Task.CompletedTask;
        }

        try
        {
            using var ad = new PrincipalContext(ContextType.Domain);
            using var user = UserPrincipal.FindByIdentity(ad, username);
            if (user is null)
            {
                return Task.CompletedTask;
            }

            using var group = GroupPrincipal.FindByIdentity(ad, requirement.GroupName);
            if (group is null)
            {
                return Task.CompletedTask;
            }

            if (user.IsMemberOf(group))
            {
                context.Succeed(requirement);
            }
        }
        catch
        {
            // Fail closed if AD is unavailable or lookup errors occur.
        }

        return Task.CompletedTask;
    }
}
