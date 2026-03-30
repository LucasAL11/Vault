using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Vault;

public class VaultConfiguration : IEntityTypeConfiguration<Domain.vault.Vault>
{
    public void Configure(EntityTypeBuilder<Domain.vault.Vault> builder)
    {
        builder.ToTable("vault");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.Name).HasMaxLength(120).IsRequired();
        builder.Property(x => x.Slug).HasMaxLength(80).IsRequired();
        builder.Property(x => x.Description).HasMaxLength(500);
        builder.Property(x => x.TenantId).HasMaxLength(80).IsRequired();
        builder.Property(x => x.Group).HasMaxLength(200).IsRequired();
        builder.Property(x => x.KeyReference).HasMaxLength(300);

        builder.Property(x => x.Status).HasConversion<int>().IsRequired();
        builder.Property(x => x.Environment).HasConversion<int>().IsRequired();
        builder.Property(x => x.RotationPeriod).IsRequired();
        builder.Property(x => x.RequireMultiFactorAuthentication).IsRequired();
        builder.Property(x => x.AllowMultiFactorAuthentication).IsRequired();

        builder.Property(x => x.RowVersion)
            .IsConcurrencyToken()
            .ValueGeneratedNever();

        builder.HasIndex(x => new { x.TenantId, x.Name }).IsUnique();
        builder.HasIndex(x => new { x.TenantId, x.Slug }).IsUnique();
        builder.HasIndex(x => new { x.TenantId, x.Status });
        builder.HasIndex(x => x.Group);
    }
}
