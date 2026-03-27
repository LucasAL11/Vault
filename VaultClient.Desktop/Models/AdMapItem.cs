namespace VaultClient.Desktop.Models;

public sealed record AdMapItem(
    Guid Id,
    string GroupId,
    string Permission,
    bool IsActive);
