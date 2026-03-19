using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Vault;

public class ADMapConfiguration : IEntityTypeConfiguration<ADMap>
{
    public void Configure(EntityTypeBuilder<ADMap> builder)
    {
        builder.ToTable("vault_ad_map");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.GroupId).HasMaxLength(300).IsRequired();
        builder.Property(x => x.Permission).HasConversion<int>().IsRequired();
        builder.Property(x => x.IsActive).IsRequired();
        builder.Property(x => x.CreatedAt).IsRequired();
        builder.Property(x => x.RowVersion).IsRowVersion();

        builder.HasIndex(x => new { x.VaultId, x.GroupId }).IsUnique();
        builder.HasIndex(x => new { x.VaultId, x.Permission, x.IsActive });
    }
}
