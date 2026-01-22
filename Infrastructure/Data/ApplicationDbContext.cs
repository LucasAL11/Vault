using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Domain.Computers;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Infrastructure.Data;

public  sealed class ApplicationDbContext(
    DbContextOptions options, 
    IMessageDispatcher publisher) 
    : DbContext(options), IApplicationDbContext 
{
    public DbSet<Computer> Computers { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
    }
    
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        int result = 1;
        await PublishDomainEventsAsync();

        return result;
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