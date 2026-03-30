using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Security.Principal;
using Application.Authentication;
using Domain.Users;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Infrastructure.Authentication;

public class UserContext : IUserContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ActiveDirectoryOptions _adOptions;

    public UserContext(
        IHttpContextAccessor httpContextAccessor,
        IOptions<ActiveDirectoryOptions> adOptions)
    {
        _httpContextAccessor = httpContextAccessor;
        _adOptions = adOptions.Value;
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
                if (!_adOptions.Enabled)
                {
                    return new HashSet<UserGroup>();
                }

                var username = Identity.Username;
                if (string.IsNullOrWhiteSpace(username) || username.Equals("anonymous", StringComparison.OrdinalIgnoreCase))
                {
                    return new HashSet<UserGroup>();
                }

                using var ad = BuildPrincipalContext();
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

    public List<string> IsInGroup { get; } = new();

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

        if (!_adOptions.Enabled)
        {
            return false;
        }

        using var ad = BuildPrincipalContext();
        using var user = UserPrincipal.FindByIdentity(ad, commandUsername);

        return user?.Enabled == true;
    }

    public IReadOnlySet<UserGroup> GetGroupsForUser(string username)
    {
        if (string.IsNullOrWhiteSpace(username) || !_adOptions.Enabled)
            return new HashSet<UserGroup>();

        try
        {
            using var ad = BuildPrincipalContext();
            using var user =
                UserPrincipal.FindByIdentity(ad, IdentityType.SamAccountName, username)
                ?? UserPrincipal.FindByIdentity(ad, username);

            if (user is null)
                return new HashSet<UserGroup>();

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

    public bool ValidateCredentials(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return false;

        if (!_adOptions.Enabled)
            return false;

        try
        {
            using var ad = BuildPrincipalContext();
            return ad.ValidateCredentials(username, password);
        }
        catch
        {
            return false;
        }
    }

    private PrincipalContext BuildPrincipalContext()
    {
        if (!string.IsNullOrWhiteSpace(_adOptions.Domain) && !string.IsNullOrWhiteSpace(_adOptions.Container))
        {
            return new PrincipalContext(ContextType.Domain, _adOptions.Domain, _adOptions.Container);
        }

        if (!string.IsNullOrWhiteSpace(_adOptions.Domain))
        {
            return new PrincipalContext(ContextType.Domain, _adOptions.Domain);
        }

        return new PrincipalContext(ContextType.Domain);
    }
}
