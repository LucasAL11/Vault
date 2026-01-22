using Application.Abstractions.Messaging.Handlers;
using Domain.Computers;
using Domain.Computers.Events;

namespace Application.Computers;

public class ComputerRegisteredDomainEventHandler : INotificationHandler<ComputerRegisteredDomainEvent>
{
    public Task Handle(ComputerRegisteredDomainEvent notification, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}