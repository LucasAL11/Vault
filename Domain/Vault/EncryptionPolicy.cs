namespace Domain.vault;

/// <summary>
/// Política de proteção criptográfica utilizada no cofre.
/// </summary>
public enum EncryptionPolicy
{
    /// <summary>Chave local ou KMS interno.</summary>
    LocalKms,
    /// <summary>KMS externo ao serviço principal.</summary>
    ExternalKms,
    /// <summary>HSM dedicado para operações criptográficas.</summary>
    Hsm
}
