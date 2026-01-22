using System.Reflection;
using Application.Abstractions.Data;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDatabase(configuration);
        return services;
    }

    private static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        string? connectionString = configuration.GetConnectionString("Database");

        services
            .AddDbContext<ApplicationDbContext>((options)
                => options
                    .UseNpgsql(
                        connectionString,
                        npgsqlOptionsAction
                            => npgsqlOptionsAction
                                .MigrationsHistoryTable(HistoryRepository.DefaultTableName))
                    .UseSnakeCaseNamingConvention()
                );
        
        services.AddScoped<IApplicationDbContext>(sp  => sp.GetRequiredService<ApplicationDbContext>());
        return services;
    }
}