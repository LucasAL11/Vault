using Domain.Computers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Computers;

public class ComputerConfiguration : IEntityTypeConfiguration<Computer>
{
    public void Configure(EntityTypeBuilder<Computer> builder)
    {
        builder.ToTable("Computers");
        
        builder.HasKey(x => x.Id);
        
        builder
            .Property(x => x.Name)
            .IsRequired()
            .HasMaxLength(250);

        builder.OwnsOne(c => c.CpuId, cpu =>
        {
            cpu.Property(p => p.Value)
                .HasColumnName("CpuId")
                .IsRequired();
        });
        
        builder.OwnsOne(c => c.Bios, cpu =>
        {
            cpu.Property(p => p.Serial)
                .HasColumnName("BiosSerial")
                .IsRequired();
        });
        
        builder.OwnsOne(c => c.Disk, disk =>
        {
            disk.Property(p => p.Serial)
                .HasColumnName("DiskSerial")
                .IsRequired();
        });

        builder.OwnsOne(c => c.MachineGuid, mg =>
        {
            mg.Property(p => p.Value)
                .HasColumnName("MachineGuid")
                .IsRequired();
        });

        builder.Property(c => c.OperatingSystem)
            .HasColumnName("OperatingSystem")
            .HasConversion(
                os => os.Value,
                value => new InternalOperatingSystem(value)
            )
            .IsRequired();
        
        builder.Property(c => c.FirstSeen)
            .HasColumnName("primeiroacesso")
            .IsRequired();
        
        builder.Property(c => c.LastSeen)
            .HasColumnName("segundoacesso")
            .IsRequired();
        
        builder.Property(c => c.IsActive)
            .HasColumnName("ativo")
            .IsRequired();

        builder.Ignore(c => c.Hwid);
    }
}