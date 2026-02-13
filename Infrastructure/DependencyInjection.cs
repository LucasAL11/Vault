using System.Text;
using Application.Abstractions.Data;
using Application.Authentication;
using Infrastructure.Authentication;
using Infrastructure.Authentication.ActiveDirectory;
using Infrastructure.Authentication.Jwt;
using Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Shared;

namespace Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDatabase(configuration);
        services.AddHttpContextAccessor();

        services.AddJwtAuthentication(configuration);
        services.AddScoped<IUserContext, UserContext>();
        services.AddSingleton<ITokenProvider, JwtTokenProvider>();
        services.AddSingleton<IDateTimeProvider, SystemDateTimeProvider>();

        services.AddSingleton<IAuthorizationPolicyProvider, AdGroupPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, AdGroupAuthorizationHandler>();

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

    private static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var jwtOptions = configuration.GetSection("Jwt").Get<JwtOptions>()
                         ?? throw new InvalidOperationException("JWT configuration section 'Jwt' is missing.");

        if (string.IsNullOrWhiteSpace(jwtOptions.Secret))
        {
            throw new InvalidOperationException("JWT secret is missing.");
        }

        services.Configure<JwtOptions>(configuration.GetSection("Jwt"));

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Secret));

        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = "BearerOrNegotiate";
                options.DefaultChallengeScheme = "BearerOrNegotiate";
            })
            .AddPolicyScheme("BearerOrNegotiate", "Bearer or Negotiate", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
                    return authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true
                        ? JwtBearerDefaults.AuthenticationScheme
                        : NegotiateDefaults.AuthenticationScheme;
                };
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtOptions.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1),
                    NameClaimType = System.Security.Claims.ClaimTypes.Name
                };
            })
            .AddNegotiate();
        
      
        services.AddAuthorization();

        return services;
    }
}
