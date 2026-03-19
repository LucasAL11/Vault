using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Vault;

public class VaultMachineConfiguration : IEntityTypeConfiguration<VaultMachine>
{
    public void Configure(EntityTypeBuilder<VaultMachine> builder)
    {
        builder.ToTable("vault_machines");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.Status).HasConversion<int>().IsRequired();
        builder.Property(x => x.CreatedAt).IsRequired();
        builder.Property(x => x.RowVersion).IsRowVersion();

        builder.HasIndex(x => new { x.VaultId, x.ComputerId }).IsUnique();
        builder.HasIndex(x => new { x.VaultId, x.Status });

        builder.HasOne<Domain.Computers.Computer>()
            .WithMany()
            .HasForeignKey(x => x.ComputerId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
