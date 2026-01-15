using Application.Abstractions.Messaging.Handlers;
using Domain.Test;

namespace Application.Test;

public class TestDomainEventHandler : INotificationHandler<TestDomainEvent>
{
    public Task Handle(TestDomainEvent notification, CancellationToken cancellationToken = default)
    {
        
        return Task.CompletedTask;
    }
}