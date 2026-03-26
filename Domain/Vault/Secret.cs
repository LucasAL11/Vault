
namespace Domain.vault;

/// <summary>
/// Representa um segredo lógico pertencente a um cofre, com versionamento.
/// </summary>
public class Secret
{
    /// <summary>Identificador único do segredo.</summary>
    public Guid Id {get; init;}
    /// <summary>Identificador do cofre ao qual o segredo pertence.</summary>
    public Guid VaultId {get; init;}
    
    /// <summary>Nome funcional do segredo (ex.: DB_PASSWORD).</summary>
    public string Name {get; init;}
    
    /// <summary>Número da versão atual ativa do segredo.</summary>
    public int CurrentVersion {get; set;}
    /// <summary>Status atual do segredo.</summary>
    public Status Status {get; private set;}
    
    /// <summary>Controle de concorrência otimista da entidade.</summary>
    public byte[] RowVersion {get; init;}

    /// <summary>Coleção somente leitura com o histórico de versões do segredo.</summary>
    private readonly List<SecretVersion> _versions = [];
    /// <summary>Histórico de versões do segredo.</summary>
    public IReadOnlyCollection<SecretVersion> Versions => _versions;
    
    private Secret(){}

    public Secret(Guid vaultId, string name)
    {
        Id = Guid.NewGuid();
        VaultId = vaultId;
        Name = name.Trim();
        Status = Status.Active;
    }

    public void Disable() => Status = Status.Disabled;

    public SecretVersion AddVersion
    (byte[] cipherText,
        byte[] nonce,
        string keyReference,
        string contentType, DateTimeOffset? expires = null)
    {
        var next = CurrentVersion + 1;

        var version = new SecretVersion(
            Id, next,cipherText,nonce,keyReference,contentType, expires);
        
        _versions.Add(version);
        CurrentVersion = next;
        
        return version;
    }
    
}
