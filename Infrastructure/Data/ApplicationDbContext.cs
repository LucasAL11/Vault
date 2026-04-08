using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Domain.Computers;
using Domain.Users;
using Domain.vault;
using Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Shared;
using System.Security.Cryptography;

namespace Infrastructure.Data;

public  sealed class ApplicationDbContext(
    DbContextOptions options, 
    IMessageDispatcher publisher) 
    : DbContext(options), IApplicationDbContext 
{
    public DbSet<Computer> Computers { get; set; }
    public DbSet<Domain.vault.Vault> Vaults { get; set; }
    public DbSet<Secret> Secrets { get; set; }
    public DbSet<SecretVersion> SecretVersions { get; set; }
    public DbSet<SecretAuditEntry> SecretAuditEntries { get; set; }
    public DbSet<VaultMachine> VaultMachines { get; set; }
    public DbSet<ADMap> ADMaps { get; set; }
    public DbSet<AutofillRule> AutofillRules { get; set; }
    public DbSet<NonceStoreEntry> NonceStoreEntries { get; set; }
    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

        if (string.Equals(Database.ProviderName, "Microsoft.EntityFrameworkCore.Sqlite", StringComparison.Ordinal))
        {
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                var rowVersionProperty = entityType.FindProperty("RowVersion");
                if (rowVersionProperty is null || rowVersionProperty.ClrType != typeof(byte[]))
                {
                    continue;
                }

                rowVersionProperty.ValueGenerated = ValueGenerated.Never;
                rowVersionProperty.SetBeforeSaveBehavior(PropertySaveBehavior.Save);
                rowVersionProperty.SetAfterSaveBehavior(PropertySaveBehavior.Save);
            }
        }
    }
    
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        EnsureRowVersionValues();

        var result = await base.SaveChangesAsync(cancellationToken);
        await PublishDomainEventsAsync();

        return result;
    }

    private void EnsureRowVersionValues()
    {
        foreach (var entry in ChangeTracker.Entries().Where(x => x.State is EntityState.Added or EntityState.Modified))
        {
            var rowVersionProperty = entry.Properties.FirstOrDefault(x =>
                x.Metadata.Name == "RowVersion" &&
                x.Metadata.ClrType == typeof(byte[]));

            if (rowVersionProperty is null)
            {
                continue;
            }

            var current = rowVersionProperty.CurrentValue as byte[];
            if (current is null || current.Length == 0)
            {
                rowVersionProperty.CurrentValue = RandomNumberGenerator.GetBytes(8);
            }
        }
    }

    private async Task PublishDomainEventsAsync()
    {
        var domainEvents =
            ChangeTracker
                .Entries<Entity>()
                .Select(entry => entry.Entity)
                .SelectMany(entity =>
                {
                    List<IDomainEvent> domainEvents = entity.DomainEvents.ToList();
                    
                    entity.ClearDomainEvents();
                    return domainEvents;
                })
                .ToList();

        foreach (var domainEvent in domainEvents)
        {
            await publisher.Publish(domainEvent);
        }

    }
}
