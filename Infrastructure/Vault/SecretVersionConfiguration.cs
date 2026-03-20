using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Vault;

public class SecretVersionConfiguration : IEntityTypeConfiguration<SecretVersion>
{
    public void Configure(EntityTypeBuilder<SecretVersion> builder)
    {
        builder.ToTable("vault_secret_versions");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.Version).IsRequired();
        builder.Property(x => x.CipherText).IsRequired();
        builder.Property(x => x.Nonce).IsRequired();
        builder.Property(x => x.KeyReference).HasMaxLength(300).IsRequired();
        builder.Property(x => x.ContentType).HasMaxLength(80).IsRequired();

        builder.HasIndex(x => new { x.SecretId, x.Version }).IsUnique();
        builder.HasIndex(x => new { x.SecretId, x.IsRevoked, x.Version });
        builder.HasIndex(x => new { x.SecretId, x.Expires });
    }
}
