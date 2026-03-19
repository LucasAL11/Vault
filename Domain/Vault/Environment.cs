namespace Domain.vault;

/// <summary>
/// Define o ambiente de execução associado ao Vault.
/// </summary>
public enum Environment
{
    /// <summary>Ambiente de produção.</summary>
    Production,
    /// <summary>Ambiente de homologação/staging.</summary>
    Staging,
    /// <summary>Ambiente de desenvolvimento.</summary>
    Development
}
