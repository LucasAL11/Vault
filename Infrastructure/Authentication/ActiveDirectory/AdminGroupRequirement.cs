using Microsoft.AspNetCore.Authorization;

namespace Infrastructure.Authentication.ActiveDirectory;

/// <summary>
/// Authorization requirement that succeeds if the user belongs to ANY of the specified admin groups.
/// Group names are loaded from appsettings: Authorization:AdminGroups
/// </summary>
public sealed class AdminGroupRequirement(string[] adminGroups) : IAuthorizationRequirement
{
    public string[] AdminGroups { get; } = adminGroups;
}
