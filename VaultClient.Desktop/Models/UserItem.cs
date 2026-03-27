namespace VaultClient.Desktop.Models;

public sealed record UserItem(
    Guid Id,
    string Username,
    string FirstName,
    string LastName);
