using Shared;

namespace Domain.Computers.Events;

public sealed record ComputerRegisteredDomainEvent(
    int ComputerId, 
    string ComputerName)
    : IDomainEvent;