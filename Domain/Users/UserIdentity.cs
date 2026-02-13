namespace Domain.Users;

public record UserIdentity(string Domain, string Username)
{
    public override string ToString() => $"{Domain}\\{Username}";
};