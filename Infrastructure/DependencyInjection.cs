using System.Text;
using Application.Abstractions.Data;
using Application.Abstractions.Cryptography;
using Application.Abstractions.Security;
using Application.Authentication;
using Infrastructure.Authentication;
using Infrastructure.Authentication.ActiveDirectory;
using Infrastructure.Authentication.Kerberos;
using Infrastructure.Authentication.Jwt;
using Infrastructure.Authentication.Oidc;
using Infrastructure.BackgroundJobs;
using Infrastructure.Data;
using Infrastructure.Security;
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
    private const string HybridScheme = "HybridAuth";
    private const string LocalJwtScheme = "LocalJwt";
    private const string OidcJwtScheme = "OidcJwt";

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
        services.AddScoped<IAuthorizationHandler, AdminGroupAuthorizationHandler>();

        services.AddKeyProvider(configuration);
        services.AddNonceStore(configuration);
        services.AddSingleton<ISecretProtector, ChaCha20SecretProtector>();

        services.Configure<SecretRenewalOptions>(configuration.GetSection("SecretRenewal"));
        services.AddHostedService<SecretVersionRenewalService>();

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
        var oidcOptions = configuration.GetSection("Authentication:Oidc").Get<OidcAuthenticationOptions>() ?? new OidcAuthenticationOptions();
        var kerberosOptions = configuration.GetSection("Authentication:Kerberos").Get<KerberosAuthenticationOptions>() ?? new KerberosAuthenticationOptions();

        if (string.IsNullOrWhiteSpace(jwtOptions.Secret))
        {
            throw new InvalidOperationException("JWT secret is missing.");
        }

        if (oidcOptions.Enabled &&
            string.IsNullOrWhiteSpace(oidcOptions.Authority) &&
            string.IsNullOrWhiteSpace(oidcOptions.Issuer))
        {
            throw new InvalidOperationException("Authentication:Oidc is enabled but both Authority and Issuer are missing.");
        }

        services.Configure<JwtOptions>(configuration.GetSection("Jwt"));
        services.Configure<OidcAuthenticationOptions>(configuration.GetSection("Authentication:Oidc"));
        services.Configure<KerberosAuthenticationOptions>(configuration.GetSection("Authentication:Kerberos"));
        services.Configure<ActiveDirectoryOptions>(configuration.GetSection("Authentication:Ldap"));

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Secret));

        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = HybridScheme;
                options.DefaultAuthenticateScheme = HybridScheme;
                options.DefaultChallengeScheme = HybridScheme;
                options.DefaultForbidScheme = HybridScheme;
            })
            .AddPolicyScheme(HybridScheme, "Hybrid LocalJwt/Oidc/Kerberos", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
                    if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        return IsOidcToken(authHeader, oidcOptions)
                            ? OidcJwtScheme
                            : LocalJwtScheme;
                    }

                    return kerberosOptions.Enabled
                        ? NegotiateDefaults.AuthenticationScheme
                        : LocalJwtScheme;
                };
            })
            .AddJwtBearer(LocalJwtScheme, options =>
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
            });

        if (oidcOptions.Enabled)
        {
            services.AddAuthentication().AddJwtBearer(OidcJwtScheme, options =>
            {
                if (!string.IsNullOrWhiteSpace(oidcOptions.Authority))
                {
                    options.Authority = oidcOptions.Authority;
                }

                options.RequireHttpsMetadata = oidcOptions.RequireHttpsMetadata;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = !string.IsNullOrWhiteSpace(oidcOptions.Issuer),
                    ValidIssuer = oidcOptions.Issuer,
                    ValidateAudience = !string.IsNullOrWhiteSpace(oidcOptions.Audience),
                    ValidAudience = oidcOptions.Audience,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1),
                    RoleClaimType = oidcOptions.RoleClaimType,
                    NameClaimType = oidcOptions.NameClaimType
                };
            });
        }

        if (kerberosOptions.Enabled)
        {
            services.AddAuthentication().AddNegotiate();
        }
        
      
        services.AddAuthorization();

        return services;
    }

    private static bool IsOidcToken(string authorizationHeader, OidcAuthenticationOptions oidcOptions)
    {
        if (!oidcOptions.Enabled)
        {
            return false;
        }

        var token = authorizationHeader["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        try
        {
            var parsed = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ReadJwtToken(token);
            var issuer = parsed.Issuer?.Trim();
            if (string.IsNullOrWhiteSpace(issuer))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(oidcOptions.Issuer) &&
                string.Equals(issuer, oidcOptions.Issuer, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(oidcOptions.Authority) &&
                issuer.StartsWith(oidcOptions.Authority.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static IServiceCollection AddKeyProvider(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<KeyProviderOptions>(configuration.GetSection("KeyProvider"));

        var keyProviderOptions = configuration.GetSection("KeyProvider").Get<KeyProviderOptions>() ?? new KeyProviderOptions();
        var mode = keyProviderOptions.Mode.Trim();

        if (string.Equals(mode, "ProdKms", StringComparison.OrdinalIgnoreCase))
        {
            var kms = keyProviderOptions.ProdKms;
            if (!Uri.TryCreate(kms.BaseUrl, UriKind.Absolute, out var baseUri))
            {
                throw new InvalidOperationException("KeyProvider:ProdKms:BaseUrl must be a valid absolute URI.");
            }

            services.AddHttpClient("KmsKeyProvider", client =>
            {
                client.BaseAddress = baseUri;
                client.Timeout = TimeSpan.FromSeconds(kms.TimeoutSeconds <= 0 ? 5 : kms.TimeoutSeconds);
            });

            services.AddSingleton<IKeyProvider, KmsKeyProvider>();
            return services;
        }

        if (string.Equals(mode, "Prod", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<IKeyProvider, ProdKeyProvider>();
            return services;
        }

        services.AddSingleton<IKeyProvider, DevKeyProvider>();
        return services;
    }

    private static IServiceCollection AddNonceStore(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<NonceStoreOptions>(configuration.GetSection("NonceStore"));

        var nonceStoreOptions = configuration.GetSection("NonceStore").Get<NonceStoreOptions>() ?? new NonceStoreOptions();
        var provider = nonceStoreOptions.Provider?.Trim() ?? NonceStoreProviders.InMemory;

        if (string.Equals(provider, NonceStoreProviders.Postgres, StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<INonceStore, PostgresNonceStore>();
            return services;
        }

        if (string.Equals(provider, NonceStoreProviders.InMemory, StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<INonceStore, InMemoryNonceStore>();
            return services;
        }

        throw new InvalidOperationException(
            $"NonceStore:Provider '{provider}' is invalid. Allowed values: '{NonceStoreProviders.InMemory}' or '{NonceStoreProviders.Postgres}'.");
    }
}
