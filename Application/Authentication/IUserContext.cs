using Domain.Users;

namespace Application.Authentication;

public interface IUserContext
{
    UserIdentity Identity { get; }
    IReadOnlySet<UserGroup> Groups { get; }
    List<string> IsInGroup  { get; }
    bool IsSameDomain(string userDomain);
    bool IsUserActive(string commandUsername);
}