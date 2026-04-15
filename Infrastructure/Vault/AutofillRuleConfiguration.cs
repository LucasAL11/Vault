using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Vault;

public class AutofillRuleConfiguration : IEntityTypeConfiguration<AutofillRule>
{
    public void Configure(EntityTypeBuilder<AutofillRule> builder)
    {
        builder.ToTable("vault_autofill_rules");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.UrlPattern).HasMaxLength(2000).IsRequired();
        builder.Property(x => x.Login).HasMaxLength(300).IsRequired();
        builder.Property(x => x.SecretName).HasMaxLength(120).IsRequired();
        builder.Property(x => x.IsActive).IsRequired();
        builder.Property(x => x.CreatedAt).IsRequired();
        builder.Property(x => x.RowVersion)
            .IsConcurrencyToken()
            .ValueGeneratedNever();

        builder.HasIndex(x => new { x.VaultId, x.UrlPattern, x.Login }).IsUnique();
        builder.HasIndex(x => new { x.VaultId, x.IsActive });
        builder.HasIndex(x => x.UrlPattern);
    }
}
