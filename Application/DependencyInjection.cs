using System.Reflection;
using Application.Abstractions.Messaging;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Application.Test;
using Domain.Test;
using Microsoft.Extensions.DependencyInjection;

namespace Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddScoped<IMessageDispatcher, MessageDispatcher>();
        
        var assembly = Assembly.GetExecutingAssembly();
        
        RegisterCommandHandlers(services, assembly);
        RegisterQueryHandlers(services, assembly);

        services.AddScoped<INotificationHandler<TestDomainEvent>, TestDomainEventHandler>();
        
        
        return services;
    }

    private static void RegisterQueryHandlers(IServiceCollection services, Assembly assembly)
    {
        var queryHandlers =
            assembly
                .GetTypes()
                .Where(t =>
                    t.GetInterfaces()
                        .Any(i => 
                            i.IsGenericType &&
                            i.GetGenericTypeDefinition() == typeof(IQueryHandler<,>)));

        foreach (var handlerType in queryHandlers)
        {
            var handlerInterface = 
                handlerType
                    .GetInterfaces()
                    .FirstOrDefault(i => 
                        i.IsGenericType &&
                        i.GetGenericTypeDefinition() == typeof(IQueryHandler<,>));
            
            services.AddScoped(handlerInterface, handlerType);
        }
    }

    private static void RegisterCommandHandlers(IServiceCollection services, Assembly assembly)
    {
        var commandHandlers = 
            assembly
                .GetTypes()
                .Where(t =>
                    t.GetInterfaces()
                        .Any(i => 
                            i.IsGenericType && 
                            (i.GetGenericTypeDefinition() == typeof(ICommandHandler<>) 
                            || i.GetGenericTypeDefinition() == typeof(ICommandHandler<,>))
                            )
                    );
        
        foreach (var handlerType in commandHandlers)
        {
            var handledInterface = 
                handlerType
                    .GetInterfaces()
                    .First(i => 
                        i.IsGenericType &&
                        (i.GetGenericTypeDefinition() == typeof(ICommand<>)
                        || i. GetGenericTypeDefinition() == typeof(ICommandHandler<,>)));
            
            services.AddScoped(handledInterface, handlerType);
        }
    }
}