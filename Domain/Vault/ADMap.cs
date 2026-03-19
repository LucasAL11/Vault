using Shared;

namespace Domain.vault;

/// <summary>
/// Mapeia grupos AD para permiss�es em um Vault.
/// </summary>
public class ADMap : Entity
{
    /// <summary>Identificador �nico do mapeamento.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>Identificador do Vault ao qual a regra pertence.</summary>
    public Guid VaultId { get; init; }

    /// <summary>Identificador do grupo AD (SID, DN ou nome can�nico).</summary>
    public string GroupId { get; private set; }

    /// <summary>N�vel de permiss�o concedido ao grupo.</summary>
    public VaultPermission Permission { get; private set; }

    /// <summary>Indica se o mapeamento est� ativo.</summary>
    public bool IsActive { get; private set; } = true;

    /// <summary>Data/hora de cria��o do mapeamento.</summary>
    public new DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.UtcNow;

    /// <summary>Controle de concorr�ncia otimista.</summary>
    public byte[] RowVersion { get; init; } = Array.Empty<byte>();

    private ADMap() { }

    public ADMap(Guid vaultId, string groupId, VaultPermission permission)
    {
        VaultId = vaultId;
        GroupId = groupId.Trim();
        Permission = permission;
    }

    public void UpdatePermission(VaultPermission permission) => Permission = permission;

    public void Disable() => IsActive = false;

    public void Enable() => IsActive = true;
}

/// <summary>
/// Permiss�es poss�veis de um grupo AD dentro de um Vault.
/// </summary>
public enum VaultPermission
{
    /// <summary>Somente leitura de segredos.</summary>
    Read = 1,
    /// <summary>Leitura e rota��o/atualiza��o de segredos.</summary>
    Write = 2,
    /// <summary>Controle administrativo completo do Vault.</summary>
    Admin = 3
}
