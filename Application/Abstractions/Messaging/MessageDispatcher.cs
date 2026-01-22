using System.Collections.Concurrent;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.Extensions.DependencyInjection;
using Shared;

namespace Application.Abstractions.Messaging;

public class MessageDispatcher : IMessageDispatcher
{
    private readonly ConcurrentDictionary<Type, Func<object, Task<Result>>> _handlers;
    private readonly ConcurrentDictionary<Type, Func<object, Task<Result>>> _handlersWithResponse;
    private readonly IServiceProvider _serviceProvider;
    private readonly ConcurrentDictionary<Type, Type> _notificationHandlerTypes;
    private readonly ConcurrentDictionary<Type, Func<object, CancellationToken, Task>> _eventDispatchers
        = new();


    public MessageDispatcher(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
        _handlers = new ConcurrentDictionary<Type, Func<object, Task<Result>>>();
        _handlersWithResponse = new ConcurrentDictionary<Type, Func<object, Task<Result>>>();
        _notificationHandlerTypes = new ConcurrentDictionary<Type, Type>();
    }

    public void RegisterHandler<TMessage>(Func<TMessage, Task<Result>> handler) 
        where TMessage : IMessage
    {
        _handlers.TryAdd(typeof(TMessage), message => handler((TMessage)message));
    }
    
    public void RegisterHandler<TMessage, TResponse>(Func<TMessage, Task<Result<TResponse>>> handler) 
        where TMessage : IMessage<TResponse>
    {
        _handlersWithResponse.TryAdd(
            typeof(TMessage),
            async message => await handler((TMessage)message));
    }
    
    public async Task<Result<TResponse>> Send<TResponse>(IMessage<TResponse> message, CancellationToken cancellationToken = default)
    {
        var messageType = message.GetType();

        if (!_handlersWithResponse.TryGetValue(messageType, out var handler))
        {
            Type handlerType;
            if (message is IQuery<TResponse>)
            {
                handlerType = typeof(IQueryHandler<,>)
                    .MakeGenericType(messageType, typeof(TResponse));
            }
            else
            {
                handlerType = typeof(ICommandHandler<,>)
                    .MakeGenericType(messageType, typeof(TResponse));
            }
            
            var handlerInstance = 
                _serviceProvider.GetRequiredService(handlerType);
            
            var handleMethod = 
                handlerType.GetMethod("Handle");
            
            handler = async obj 
                => await (Task<Result<TResponse>>)handleMethod
                .Invoke(handlerInstance, [obj, cancellationToken]);
            
            _handlersWithResponse.TryAdd(messageType, handler);
        }
        var result = await handler(message);

        return (Result<TResponse>)result;
    }

    public async Task<Result> Send(IMessage message, CancellationToken cancellationToken = default)
    {
        var messageType = message.GetType();
        
        if (!_handlers.TryGetValue(messageType, out var handler))
        {
            var handlerType = typeof(ICommandHandler<>).MakeGenericType(messageType);
            var handlerInstance = _serviceProvider.GetRequiredService(handlerType);
            
            var handleMethod = handlerType.GetMethod("Handle");
            handler = async obj => await (Task<Result>)handleMethod.Invoke(handlerInstance, [obj, cancellationToken]);
            _handlers.TryAdd(messageType, handler);
        }
        return await handler(message);
    }

    public async Task Publish(
        IDomainEvent domainEvent, 
        CancellationToken cancellationToken = default)
    {
        var eventType = domainEvent.GetType();

        var dispatcher = _eventDispatchers.GetOrAdd(eventType, type =>
        {
            var handlersType = typeof(INotificationHandler<>).MakeGenericType(type);
            var handleMethod = handlersType.GetMethod("Handle");

            return async (evt, ct) =>
            {
                var handlers = _serviceProvider.GetServices(handlersType);

                foreach (var handler in handlers)
                {
                    await (Task)handleMethod.Invoke(handler, [evt, ct]);
                }
            };
        });
        
        await dispatcher(domainEvent, cancellationToken);
    }
}