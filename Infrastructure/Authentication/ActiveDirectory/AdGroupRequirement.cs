using Microsoft.AspNetCore.Authorization;

namespace Infrastructure.Authentication.ActiveDirectory;

public sealed class AdGroupRequirement(string groupName) : IAuthorizationRequirement
{
    public string GroupName { get; } = groupName;
}
