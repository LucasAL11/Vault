using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;

namespace Api.IntegrationTests.Infrastructure;

/// <summary>
/// Test authorization handler that succeeds for both AdGroupRequirement and
/// AdminGroupRequirement, preserving the "allow all AD group checks" contract
/// used across integration tests (the test user is treated as Admin Geral).
/// </summary>
internal sealed class AllowAllAdGroupAuthorizationHandler : IAuthorizationHandler
{
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        foreach (var requirement in context.Requirements)
        {
            switch (requirement)
            {
                case AdGroupRequirement adGroup:
                    context.Succeed(adGroup);
                    break;
                case AdminGroupRequirement admin:
                    context.Succeed(admin);
                    break;
            }
        }

        return Task.CompletedTask;
    }
}
