namespace Domain.vault;

/// <summary>
/// Trilha de auditoria para operacoes de segredo/chave.
/// </summary>
public class SecretAuditEntry
{
    public Guid Id { get; init; }
    public Guid? VaultId { get; init; }
    public string? SecretName { get; init; }
    public string Action { get; init; }
    public string Actor { get; init; }
    public DateTimeOffset OccurredAtUtc { get; init; }
    public string? Details { get; init; }

    private SecretAuditEntry() { }

    public SecretAuditEntry(
        Guid? vaultId,
        string? secretName,
        string action,
        string actor,
        DateTimeOffset occurredAtUtc,
        string? details = null)
    {
        Id = Guid.NewGuid();
        VaultId = vaultId;
        SecretName = string.IsNullOrWhiteSpace(secretName) ? null : secretName.Trim();
        Action = action.Trim();
        Actor = actor.Trim();
        OccurredAtUtc = occurredAtUtc;
        Details = string.IsNullOrWhiteSpace(details) ? null : details.Trim();
    }
}
