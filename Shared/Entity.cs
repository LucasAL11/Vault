namespace Shared;

public abstract class Entity
{
    private readonly List<IDomainEvent> _domainEvents = [];
    public List<IDomainEvent> DomainEvents => [.. _domainEvents];
    public void ClearDomainEvents() => _domainEvents.Clear();
    public void RaiseEvents(IDomainEvent domainEvent) => _domainEvents.Add(domainEvent);
    public DateTimeOffset  CreatedAt { get; }
    public DateTimeOffset UpdatedAt { get; }
    public string  CreatedBy { get; }
    public string  UpdatedBy { get; }
    
}