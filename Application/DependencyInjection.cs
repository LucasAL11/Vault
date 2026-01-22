using System.Reflection;
using Application.Abstractions.Messaging;
using Application.Abstractions.Messaging.Handlers;
using Application.Computers;
using Domain.Computers;
using Domain.Computers.Events;
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

        services.AddScoped<INotificationHandler<ComputerRegisteredDomainEvent>, ComputerRegisteredDomainEventHandler>();
        
        return services;
    }
    
    private static void RegisterQueryHandlers(IServiceCollection services, Assembly assembly)
    {
        var queryHandlers = assembly
            .GetTypes()
            .Where(t => t is { IsAbstract: false, IsInterface: false })
            .SelectMany(t => t.GetInterfaces()
                .Where(i =>
                    i.IsGenericType && 
                    i.GetGenericTypeDefinition() == typeof(IQueryHandler<,>))
                .Select(i => new { Handler = t, Interface = i}));

        foreach (var item in queryHandlers)
        {
            services.AddScoped(item.Interface, item.Handler);
        }
    }

    private static void RegisterCommandHandlers(IServiceCollection services, Assembly assembly)
    {
        var commandHandlers = 
            assembly
                .GetTypes()
                .Where(t => t is { IsAbstract: false, IsInterface: false })
                .SelectMany(t => 
                    t.GetInterfaces()
                    .Where(i => i.IsGenericType &&
                                (i.GetGenericTypeDefinition() == typeof(ICommandHandler<,>)
                                || i. GetGenericTypeDefinition() == typeof(ICommandHandler<,>)))
                    .Select(i => new { Handler = t, Interface = i }));
          
        
        foreach (var item in commandHandlers)
        {
           services.AddScoped(item.Interface, item.Handler);
        }
    }
}