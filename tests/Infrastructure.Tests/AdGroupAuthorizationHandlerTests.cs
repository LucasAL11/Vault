using System.Security.Claims;
using Application.Authentication;
using Domain.Users;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Infrastructure.Tests;

public sealed class AdGroupAuthorizationHandlerTests
{
    [Fact]
    public async Task HandleRequirement_WithRoleClaim_ShouldSucceedWithoutAdLookup()
    {
        var handler = new AdGroupAuthorizationHandler(new FakeUserContext(), NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("Administradores de Chaves");

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name, "PLT\\lucas.luna"),
                    new Claim(ClaimTypes.Role, "Administradores de Chaves")
                },
                "Bearer"));

        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);
        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirement_WithGroupsClaim_ShouldSucceedWithoutAdLookup()
    {
        var handler = new AdGroupAuthorizationHandler(new FakeUserContext(), NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("PLT\\TI");

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name, "PLT\\lucas.luna"),
                    new Claim("groups", "TI")
                },
                "Bearer"));

        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);
        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirement_WithTokenOverage_ShouldUseUserContextGroups()
    {
        var userContext = new FakeUserContext(
            new HashSet<UserGroup>
            {
                new("Administradores de Chaves")
            });
        var handler = new AdGroupAuthorizationHandler(userContext, NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("Administradores de Chaves");

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name, "PLT\\lucas.luna"),
                    new Claim("hasgroups", "true"),
                    new Claim("_claim_names", "{\"groups\":\"src1\"}")
                },
                "Bearer"));

        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);
        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    private sealed class FakeUserContext : IUserContext
    {
        private readonly IReadOnlySet<UserGroup> _groups;

        public FakeUserContext(IReadOnlySet<UserGroup>? groups = null)
        {
            _groups = groups ?? new HashSet<UserGroup>();
        }

        public UserIdentity Identity => new("PLT", "lucas.luna");
        public IReadOnlySet<UserGroup> Groups => _groups;
        public List<string> IsInGroup => new();
        public bool IsSameDomain(string userDomain) => true;
        public bool IsUserActive(string commandUsername) => true;
    }
}
