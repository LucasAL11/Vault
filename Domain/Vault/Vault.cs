using System.Net.Security;
using Domain.Enterprise;
using Shared;

namespace Domain.vault;

/// <summary>
/// Representa um cofre lógico que agrupa segredos e regras de segurança.
/// </summary>
public class Vault : Entity
{
    /// <summary>Identificador único do cofre.</summary>
    public Guid Id { get; set; }
    /// <summary>Nome de exibição do cofre.</summary>
    public string Name { get; private set; }
    /// <summary>Nome técnico curto usado para identificação estável.</summary>
    public string Slug { get; init; }
    /// <summary>Descrição funcional do cofre.</summary>
    public string Description { get; private set; }
    /// <summary>Identificador do tenant proprietário do cofre.</summary>
    public string TenantId { get; init; }
    /// <summary>Ambiente operacional do cofre (produção, staging, desenvolvimento).</summary>
    public Environment Environment {get; init;}
    /// <summary>Status atual do cofre.</summary>
    public Status Status {get; set;}
    /// <summary>Grupo de acesso proprietário do cofre.</summary>
    public string Group {get; init;}
    /// <summary>Referência da chave criptográfica externa, quando aplicável.</summary>
    public string? KeyReference {get; init;}
    /// <summary>Periodicidade de rotação de chave/segredo em dias.</summary>
    public int RotationPeriod {get; init;}
    /// <summary>Data da última rotação registrada.</summary>
    public DateTimeOffset? LastRotation {get; private set;}
    /// <summary>Indica se MFA é exigido para operações de leitura/acesso.</summary>
    public bool RequireMultiFactorAuthentication {get; init;}
    /// <summary>Indica se fluxo de acesso emergencial com MFA é permitido.</summary>
    public bool AllowMultiFactorAuthentication {get; init;}
    /// <summary>Controle de concorrência otimista da entidade.</summary>
    public byte[] RowVersion {get; init;} = Array.Empty<byte>();

    public string Owner { get; private set; }
    public EncryptionPolicy EncryptionPolicy { get; set; } 
        = EncryptionPolicy.LocalKms;

    private Vault(){}

    public Vault(
        string tenantId,
        string name,
        string slug,
        string group,
        Environment environment = Environment.Production,
        string? owner = null)
    {
        TenantId = tenantId;
        Name = name;
        Slug = slug;
        Group = group;
        Environment = environment;
        Owner = owner ?? string.Empty;
    }

    public void UpdateDescription(string description, string updatedBy)
    {
        Description = description.Trim();
    }

    public void Update(string name, string description)
    {
        if (!string.IsNullOrWhiteSpace(name))
            Name = name.Trim();
        Description = description?.Trim() ?? Description;
    }

    public void MarkRotate(string updatedBy)
    {
        LastRotation = DateTimeOffset.UtcNow;
    }

    public void Disable()
    {
        Status = Status.Disabled;
    }
    
    
}
