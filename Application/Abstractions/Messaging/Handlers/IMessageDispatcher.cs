using Application.Abstractions.Messaging.Message;
using Shared;

namespace Application.Abstractions.Messaging.Handlers;

public interface IMessageDispatcher
{
    Task<Result<TResponse>> Send<TResponse>(IMessage<TResponse> message,  CancellationToken cancellationToken = default);
    Task<Result> Send(IMessage message, CancellationToken cancellationToken = default);
    Task Publish(IDomainEvent domainEvent, CancellationToken cancellationToken = default);
}