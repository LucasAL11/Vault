using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Security;

public sealed class NonceStoreEntryConfiguration : IEntityTypeConfiguration<NonceStoreEntry>
{
    public void Configure(EntityTypeBuilder<NonceStoreEntry> builder)
    {
        builder.ToTable("nonce_store_entries");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.Scope).HasMaxLength(300).IsRequired();
        builder.Property(x => x.NonceHash).HasMaxLength(64).IsRequired();
        builder.Property(x => x.CreatedAtUtc).IsRequired();
        builder.Property(x => x.ExpiresAtUtc).IsRequired();

        builder.HasIndex(x => new { x.Scope, x.NonceHash }).IsUnique();
        builder.HasIndex(x => x.ExpiresAtUtc);
    }
}
