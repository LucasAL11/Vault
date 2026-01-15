using Application.Abstractions.Messaging.Message;
using Shared;

namespace Application.Abstractions.Messaging.Handlers;

public interface ICommandHandler<in TCommand> 
    where TCommand : ICommand
{
    Task<Result> Handle(TCommand command, CancellationToken cancellationToken = default);
}

public interface ICommandHandler<in TCommand, TResponse>
    where TCommand : ICommand<TResponse>
{
    Task<Result<TResponse>> Handle(TCommand command, CancellationToken cancellationToken = default);
}