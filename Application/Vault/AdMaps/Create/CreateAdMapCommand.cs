using Application.Abstractions.Messaging.Message;
using Domain.vault;

namespace Application.Vault.AdMaps.create;

public sealed record CreateAdMapCommand(
    Guid VaultId,
    string GroupId,
    VaultPermission Permission,
    bool IsActive) : ICommand<AdMapDto>;