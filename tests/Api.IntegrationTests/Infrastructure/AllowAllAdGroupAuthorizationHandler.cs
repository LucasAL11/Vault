using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;

namespace Api.IntegrationTests.Infrastructure;

internal sealed class AllowAllAdGroupAuthorizationHandler : AuthorizationHandler<AdGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdGroupRequirement requirement)
    {
        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
