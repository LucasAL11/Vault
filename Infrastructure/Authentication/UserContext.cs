using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Security.Principal;
using Application.Authentication;
using Domain.Users;
using Microsoft.AspNetCore.Http;

namespace Infrastructure.Authentication;

public class UserContext : IUserContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserContext(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public UserIdentity Identity
    {
        get
        {
            var user = _httpContextAccessor.HttpContext?.User;
            var name = user?.Identity?.Name;

            if (!string.IsNullOrWhiteSpace(name))
            {
                var parts = name.Split('\\', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2)
                {
                    return new UserIdentity(parts[0], parts[1]);
                }
            }

            var username = user?.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!string.IsNullOrWhiteSpace(username))
            {
                return new UserIdentity(Environment.UserDomainName, username);
            }

            return new UserIdentity("Unknown", "anonymous");
        }
    }

    public IReadOnlySet<UserGroup> Groups
    {
        get
        {
            var windowsGroups = (_httpContextAccessor.HttpContext?.User.Identity as WindowsIdentity)?
                .Groups?
                .Select(g => g.Translate(typeof(NTAccount)).Value)
                .Select(g => new UserGroup(g.Split('\\').Last()))
                .ToHashSet();

            if (windowsGroups is { Count: > 0 })
            {
                return windowsGroups;
            }

            try
            {
                var username = Identity.Username;
                if (string.IsNullOrWhiteSpace(username) || username.Equals("anonymous", StringComparison.OrdinalIgnoreCase))
                {
                    return new HashSet<UserGroup>();
                }

                using var ad = new PrincipalContext(ContextType.Domain);
                using var user =
                    UserPrincipal.FindByIdentity(ad, IdentityType.SamAccountName, username)
                    ?? UserPrincipal.FindByIdentity(ad, username);

                if (user is null)
                {
                    return new HashSet<UserGroup>();
                }

                return user.GetAuthorizationGroups()
                    .OfType<GroupPrincipal>()
                    .Select(g => g.SamAccountName ?? g.Name)
                    .Where(g => !string.IsNullOrWhiteSpace(g))
                    .Select(g => new UserGroup(g!))
                    .ToHashSet();
            }
            catch
            {
                return new HashSet<UserGroup>();
            }
        }
    }

    public List<string> IsInGroup { get; }

    public bool IsSameDomain(string userDomain)
    {
        if (string.IsNullOrWhiteSpace(userDomain))
        {
            return false;
        }

        var apiDomain = Environment.UserDomainName;

        return string.Equals(userDomain, apiDomain, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsUserActive(string commandUsername)
    {
        if (string.IsNullOrWhiteSpace(commandUsername))
        {
            return false;
        }

        using var ad = new PrincipalContext(contextType: ContextType.Domain);
        using var user = UserPrincipal.FindByIdentity(ad, commandUsername);

        return user?.Enabled == true;
    }
}
