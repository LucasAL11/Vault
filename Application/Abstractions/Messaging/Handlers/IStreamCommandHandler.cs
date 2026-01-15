using Application.Abstractions.Messaging.Message;
using Shared;

namespace Application.Abstractions.Messaging.Handlers;

public interface IStreamCommandHandler<in TCommand, TResponse> 
    where TCommand : IStreamCommand<TResponse>
{
    Task<Result<IAsyncEnumerable<TResponse>>> 
        Handle(TCommand command, CancellationToken cancellationToken = default);
}