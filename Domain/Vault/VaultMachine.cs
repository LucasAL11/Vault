using Shared;

namespace Domain.vault;

/// <summary>
/// Vincula um computador já registrado ao Vault e controla seu estado de autorização.
/// </summary>
public class VaultMachine : Entity
{
    /// <summary>Identificador único do vínculo.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>Identificador do Vault ao qual o computador está associado.</summary>
    public Guid VaultId { get; init; }

    /// <summary>Identificador do computador registrado na tabela Computers.</summary>
    public int ComputerId { get; init; }

    /// <summary>Status de autorização do vínculo no Vault.</summary>
    public VaultMachineStatus Status { get; private set; } = VaultMachineStatus.Active;

    /// <summary>Data/hora de criação do vínculo.</summary>
    public DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.UtcNow;

    /// <summary>Último momento em que o vínculo foi usado com sucesso.</summary>
    public DateTimeOffset? LastSeenAt { get; private set; }

    /// <summary>Controle de concorrência otimista.</summary>
    public byte[] RowVersion { get; init; } = Array.Empty<byte>();

    private VaultMachine() { }

    public VaultMachine(Guid vaultId, int computerId)
    {
        VaultId = vaultId;
        ComputerId = computerId;
    }

    public void MarkSeen() => LastSeenAt = DateTimeOffset.UtcNow;

    public void Disable() => Status = VaultMachineStatus.Disabled;

    public void Enable() => Status = VaultMachineStatus.Active;
}

/// <summary>
/// Status do vínculo de autorização entre Vault e Computer.
/// </summary>
public enum VaultMachineStatus
{
    /// <summary>Vínculo ativo para operações.</summary>
    Active = 1,
    /// <summary>Vínculo bloqueado.</summary>
    Disabled = 2
}
