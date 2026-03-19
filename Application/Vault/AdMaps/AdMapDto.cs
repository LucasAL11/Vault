using Domain.vault;

namespace Application.Vault.AdMaps;

public sealed record AdMapDto(
    Guid Id,
    Guid VaultId,
    string GroupId,
    VaultPermission Permission,
    bool IsActive,
    DateTimeOffset CreatedAt);
