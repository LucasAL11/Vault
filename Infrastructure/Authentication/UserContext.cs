using System.Security.Principal;
using Application.Authentication;
using Domain.Users;
using System.DirectoryServices.AccountManagement;
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
        => _httpContextAccessor
            .HttpContext?
            .User?
            .Identity?
            .Name?
            .Split('\\')
            .Select((value, index) 
                => new {value, Index = index})
            .Where(x => x.Index < 2)
            .ToArray() is {Length:2} parts
            ? new UserIdentity(parts[0].value, parts[1].value)
            : new UserIdentity("Unknown", "anonymous");

    public IReadOnlySet<UserGroup> Groups
        => (_httpContextAccessor.HttpContext?.User.Identity as WindowsIdentity)?
            .Groups?
            .Select(g => g.Translate(typeof(NTAccount)).Value)
            .Select(g => new UserGroup((g.Split('\\').Last())))
            .ToHashSet() ?? [];
    
    
    public List<string> IsInGroup { get; }

    public bool IsSameDomain(string userDomain)
    {
            if (string.IsNullOrWhiteSpace(userDomain))
                return false;
            
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