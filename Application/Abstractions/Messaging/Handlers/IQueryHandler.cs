using Application.Abstractions.Messaging.Message;
using Shared;

namespace Application.Abstractions.Messaging.Handlers;

public interface IQueryHandler<in TQuery, TResponse> 
    where TQuery : IQuery<TResponse>
{
    Task<Result<TResponse>> Handle(TQuery query, CancellationToken cancellationToken = default); 
}