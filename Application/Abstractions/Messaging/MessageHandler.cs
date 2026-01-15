using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.Extensions.DependencyInjection;
using Shared;

namespace Application.Abstractions.Messaging;

public class MessageHandler
{
    private readonly IServiceProvider _serviceProvider;
    private readonly MessageDispatcher _dispatcher;
    
    public MessageHandler(IServiceProvider serviceProvider,  MessageDispatcher dispatcher)
    {
        _serviceProvider = serviceProvider;
        _dispatcher = dispatcher;
    }

    public void RegisterHandlers()
    {
        using var scope = _serviceProvider.CreateScope();
        
        RegisterCommandHandlers(scope);
        RegisterQueryHandlers(scope);
    }

    private void RegisterQueryHandlers(IServiceScope scope)
    {
        var commandHandlers = scope.ServiceProvider
            .GetServices<ICommandHandler<ICommand>>();

        foreach (var handler in commandHandlers)
        {
            var commandType = 
                handler
                .GetType()
                .GetInterfaces()
                .First(x => x.IsGenericType 
                            && x.GetGenericTypeDefinition() 
                            == typeof(ICommandHandler<>))
                .GetGenericArguments()[0];

            var method = 
                typeof(MessageDispatcher)
                .GetMethod(nameof(MessageDispatcher.RegisterHandler),
                    [typeof(Func<>)])?
                .MakeGenericMethod(commandType);
            
            var handleDelegate = 
                (Func<ICommand, Task<Result>>)
                (command => handler.Handle(command));
            
            method?.Invoke(_dispatcher, [handleDelegate]);
        }
        
        var commandHandlersWithResponse =
            scope
                .ServiceProvider
                .GetServices<ICommandHandler<ICommand<object>, object>>();

        foreach (var handler in commandHandlersWithResponse)
        {
            var handlerType =
                handler
                    .GetType()
                    .GetInterfaces()
                    .First(x => x.IsGenericType
                                && x.GetGenericTypeDefinition()
                                == typeof(ICommandHandler<,>));
            
            var commandType = 
                handlerType
                    .GetGenericArguments()[0];
            
            var responseType = 
                handlerType
                    .GetGenericArguments()[1];
            
            var method =
                typeof(MessageDispatcher)
                    .GetMethod(nameof(MessageDispatcher.RegisterHandler),
                        [typeof(Func<,>)])?
                    .MakeGenericMethod(commandType, responseType);

            var handleDelegate =
                (Func<ICommand<object>, Task<Result<object>>>)
                (command 
                    => (Task<Result<object>>)
                    handler
                        .GetType()
                        .GetMethod(nameof(ICommandHandler<ICommand<Object>, object>.Handle))
                        ?.Invoke(handler, [command]));
            
            method?.Invoke(_dispatcher, [handleDelegate]);
        }
    }

    private void RegisterCommandHandlers(IServiceScope scope)
    {
        var queryHandlers = 
            scope
                .ServiceProvider
                .GetServices<IQueryHandler<IQuery<object>, object>>();

        foreach (var handler in queryHandlers)
        {
            var handlerType = 
                handler
                    .GetType()
                    .GetInterfaces()
                    .First(x => 
                        x.IsGenericType
                        && x.GetGenericTypeDefinition()
                            == typeof(IQueryHandler<,>));
            
            var queryType = 
                handlerType
                    .GetGenericArguments()[0];
            
            var responseType =
                handlerType
                    .GetGenericArguments()[1];
            
            var method =
                typeof(MessageDispatcher)
                    .GetMethod(nameof(MessageDispatcher.RegisterHandler), 
                        [typeof(Func<,>)])
                    ?.MakeGenericMethod(queryType, responseType);

            var handleDelegate =
                (Func<IQuery<object>, Task<Result<object>>>)
                (query => (Task<Result<object>>)
                    handler
                        .GetType()
                        .GetMethod(nameof(MessageDispatcher.RegisterHandler), 
                            [typeof(Func<,>)])?
                        .Invoke(handler, [query]));
            
            method.Invoke(_dispatcher, [handleDelegate]);
        }
    }
}