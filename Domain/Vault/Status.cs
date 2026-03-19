namespace Domain.vault;

/// <summary>
/// Representa o estado de ciclo de vida de uma entidade de Vault.
/// </summary>
public enum Status
{
    /// <summary>Ativo para uso operacional.</summary>
    Active,
    /// <summary>Desabilitado para uso temporário.</summary>
    Disabled,
    /// <summary>Arquivado e fora de operação normal.</summary>
    Archived,
    /// <summary>Expirado por política de validade.</summary>
    Expired
}
