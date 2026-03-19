using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Vault;

public class SecretAuditEntryConfiguration : IEntityTypeConfiguration<SecretAuditEntry>
{
    public void Configure(EntityTypeBuilder<SecretAuditEntry> builder)
    {
        builder.ToTable("vault_secret_audit");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.Action).HasMaxLength(120).IsRequired();
        builder.Property(x => x.Actor).HasMaxLength(200).IsRequired();
        builder.Property(x => x.SecretName).HasMaxLength(120);
        builder.Property(x => x.OccurredAtUtc).IsRequired();
        builder.Property(x => x.Details).HasMaxLength(2000);

        builder.HasIndex(x => x.OccurredAtUtc);
        builder.HasIndex(x => new { x.VaultId, x.SecretName, x.OccurredAtUtc });
        builder.HasIndex(x => x.Action);
    }
}
