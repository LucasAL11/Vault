using System.Reflection;
using Api.Endpoints;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Api.Extensions;

public static class EndpointExtensions
{
    public static IServiceCollection AddEndpoints(this IServiceCollection services, Assembly assembly)
    {
        ServiceDescriptor[] serviceDescriptors =
            assembly
                .DefinedTypes
                .Where(type => type is
                {
                    IsAbstract: false,
                    IsInterface: false
                } && type.IsAssignableTo(typeof(IEndpoint)))
                .Select(type => ServiceDescriptor.Transient(typeof(IEndpoint), type))
                .ToArray();
        
        services.TryAddEnumerable(serviceDescriptors);
        
        return services;
    }

    public static IApplicationBuilder MapEndpoints(this WebApplication application, RouteGroupBuilder? routeGroupBuilder = null)
    {
        IEnumerable<IEndpoint> endpoints = 
            application
                .Services
                .GetRequiredService<IEnumerable<IEndpoint>>();

        IEndpointRouteBuilder endpointRouteBuilder = 
            routeGroupBuilder is null 
                ? application 
                : routeGroupBuilder;

        foreach (var endpoint in endpoints)
        {
            endpoint.MapEndpoint(endpointRouteBuilder);
        }
        
        return application;
    }
    
    public static RouteGroupBuilder HasPermission(this RouteGroupBuilder routeGroupBuilder, string permission)
        => routeGroupBuilder.RequireAuthorization(permission);
}