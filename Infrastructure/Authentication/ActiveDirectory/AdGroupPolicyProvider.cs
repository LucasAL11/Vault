using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Infrastructure.Authentication.ActiveDirectory;

public sealed class AdGroupPolicyProvider : IAuthorizationPolicyProvider
{
    private const string PolicyPrefix = "AdGroup:";
    public const string AdminPolicyName = "AdminPolicy";

    private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;
    private readonly string[] _adminGroups;
    private readonly bool _bypassAdGroupCheck;

    public AdGroupPolicyProvider(IOptions<AuthorizationOptions> options, IConfiguration configuration)
    {
        _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
        _adminGroups = configuration.GetSection("Authorization:AdminGroups").Get<string[]>()
                       ?? ["Admins", "Admin", "Administrators"];
        _bypassAdGroupCheck = configuration.GetValue<bool>("Authorization:BypassAdGroupCheck");
    }

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        // AdminPolicy: user must belong to ANY of the configured admin groups
        if (string.Equals(policyName, AdminPolicyName, StringComparison.OrdinalIgnoreCase))
        {
            var policyBuilder = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser();

            if (_bypassAdGroupCheck)
            {
                // In bypass mode, any authenticated user passes
                var policy = policyBuilder.Build();
                return Task.FromResult<AuthorizationPolicy?>(policy);
            }

            // Add a requirement for each admin group — handler will succeed if user is in ANY of them
            policyBuilder.AddRequirements(new AdminGroupRequirement(_adminGroups));
            return Task.FromResult<AuthorizationPolicy?>(policyBuilder.Build());
        }

        // AdGroup:XXX — single group check
        if (policyName.StartsWith(PolicyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var groupName = policyName.Substring(PolicyPrefix.Length).Trim();
            if (string.IsNullOrWhiteSpace(groupName))
            {
                return Task.FromResult<AuthorizationPolicy?>(null);
            }

            var policyBuilder = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser();

            if (_bypassAdGroupCheck)
            {
                return Task.FromResult<AuthorizationPolicy?>(policyBuilder.Build());
            }

            policyBuilder.AddRequirements(new AdGroupRequirement(groupName));
            return Task.FromResult<AuthorizationPolicy?>(policyBuilder.Build());
        }

        return _fallbackPolicyProvider.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
        => _fallbackPolicyProvider.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
        => _fallbackPolicyProvider.GetFallbackPolicyAsync();
}
