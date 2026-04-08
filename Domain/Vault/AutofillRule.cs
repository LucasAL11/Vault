using Shared;

namespace Domain.vault;

/// <summary>
/// Regra de autofill que associa um padrão de URL a credenciais (login + segredo) dentro de um Vault.
/// </summary>
public class AutofillRule : Entity
{
    /// <summary>Identificador único da regra.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>Identificador do Vault ao qual a regra pertence.</summary>
    public Guid VaultId { get; init; }

    /// <summary>Padrão de URL do serviço (ex: "https://erp.empresa.com/*").</summary>
    public string UrlPattern { get; private set; }

    /// <summary>Nome de utilizador / login para autofill.</summary>
    public string Login { get; private set; }

    /// <summary>Nome do segredo no Vault que contém a senha.</summary>
    public string SecretName { get; private set; }

    /// <summary>Indica se a regra está ativa.</summary>
    public bool IsActive { get; private set; } = true;

    /// <summary>Data/hora de criação.</summary>
    public new DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.UtcNow;

    /// <summary>Controle de concorrência otimista.</summary>
    public byte[] RowVersion { get; init; } = Array.Empty<byte>();

    private AutofillRule() { }

    public AutofillRule(Guid vaultId, string urlPattern, string login, string secretName)
    {
        VaultId = vaultId;
        UrlPattern = urlPattern.Trim();
        Login = login.Trim();
        SecretName = secretName.Trim();
    }

    public void Update(string urlPattern, string login, string secretName)
    {
        UrlPattern = urlPattern.Trim();
        Login = login.Trim();
        SecretName = secretName.Trim();
    }

    public void Disable() => IsActive = false;

    public void Enable() => IsActive = true;
}
