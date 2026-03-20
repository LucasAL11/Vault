using System.Security.Claims;
using Application.Authentication;
using Domain.Users;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Infrastructure.Tests;

public sealed class AdGroupAuthorizationHandlerTests
{
    [Fact]
    public async Task HandleRequirement_WithRoleClaim_ShouldSucceedWithoutAdLookup()
    {
        var handler = new AdGroupAuthorizationHandler(
            new FakeUserContext(),
            Options.Create(new ActiveDirectoryOptions { Enabled = true }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
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
        var handler = new AdGroupAuthorizationHandler(
            new FakeUserContext(),
            Options.Create(new ActiveDirectoryOptions { Enabled = true }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
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
        var handler = new AdGroupAuthorizationHandler(
            userContext,
            Options.Create(new ActiveDirectoryOptions { Enabled = true }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
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

    [Fact]
    public async Task HandleRequirement_WhenLdapDisabled_AndNoMatchingClaims_ShouldFailClosed()
    {
        var handler = new AdGroupAuthorizationHandler(
            new FakeUserContext(),
            Options.Create(new ActiveDirectoryOptions { Enabled = false }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("Administradores de Chaves");

        var principal = new ClaimsPrincipal(new ClaimsIdentity(authenticationType: "Bearer"));
        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirement_WhenUsernameIsEmpty_ShouldFailClosed()
    {
        var handler = new AdGroupAuthorizationHandler(
            new FakeUserContext(identity: new UserIdentity("PLT", string.Empty)),
            Options.Create(new ActiveDirectoryOptions { Enabled = true }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("Administradores de Chaves");

        var principal = new ClaimsPrincipal(new ClaimsIdentity(authenticationType: "Bearer"));
        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirement_WithRoleClaimContainingDomainPrefix_ShouldSucceed()
    {
        var handler = new AdGroupAuthorizationHandler(
            new FakeUserContext(),
            Options.Create(new ActiveDirectoryOptions { Enabled = false }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("PLT\\Administradores de Chaves");

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name, "PLT\\lucas.luna"),
                    new Claim(ClaimTypes.Role, "CORP\\Administradores de Chaves")
                },
                "Bearer"));

        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);
        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirement_WithMismatchedClaimsAndGroups_ShouldFail()
    {
        var userContext = new FakeUserContext(new HashSet<UserGroup> { new("Finance") });
        var handler = new AdGroupAuthorizationHandler(
            userContext,
            Options.Create(new ActiveDirectoryOptions { Enabled = false }),
            NullLogger<AdGroupAuthorizationHandler>.Instance);
        var requirement = new AdGroupRequirement("Administradores de Chaves");

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name, "PLT\\lucas.luna"),
                    new Claim("groups", "Operadores")
                },
                "Bearer"));

        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, resource: null);
        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    private sealed class FakeUserContext : IUserContext
    {
        private readonly IReadOnlySet<UserGroup> _groups;
        private readonly UserIdentity _identity;

        public FakeUserContext(IReadOnlySet<UserGroup>? groups = null, UserIdentity? identity = null)
        {
            _groups = groups ?? new HashSet<UserGroup>();
            _identity = identity ?? new UserIdentity("PLT", "lucas.luna");
        }

        public UserIdentity Identity => _identity;
        public IReadOnlySet<UserGroup> Groups => _groups;
        public List<string> IsInGroup => new();
        public bool IsSameDomain(string userDomain) => true;
        public bool IsUserActive(string commandUsername) => true;
    }
}
