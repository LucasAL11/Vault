using Domain.vault;

namespace Application.Vault.Machines;

public sealed record MachineDto(
    Guid Id,
    Guid VaultId,
    int ComputerId,
    string? ComputerName,
    VaultMachineStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt);
