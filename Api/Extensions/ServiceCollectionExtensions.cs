using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.OpenApi.Models;

namespace Api.Extensions;

internal static class ServiceCollectionExtensions
{
    internal static IServiceCollection AddSwaggerGenWithAuth(this IServiceCollection services)
    {
        services.AddSwaggerGen(o =>
        {
            o.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "WebApplication1 API",
                Version = "v1"
            });

            o.CustomSchemaIds(id => id.FullName!.Replace("+", "-"));
            o.DocInclusionPredicate((documentName, apiDescription) =>
                string.Equals(apiDescription.GroupName, documentName, StringComparison.OrdinalIgnoreCase));

            var bearerSecurityScheme = new OpenApiSecurityScheme
            {
                Name = "JWT Authentication",
                Description = "Enter your JWT token in this field",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT"
            };

            o.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, bearerSecurityScheme);

            var negotiateSecurityScheme = new OpenApiSecurityScheme
            {
                Name = "Kerberos (Negotiate)",
                Description = "Browser/OS managed Kerberos challenge-response",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = NegotiateDefaults.AuthenticationScheme
            };

            o.AddSecurityDefinition(NegotiateDefaults.AuthenticationScheme, negotiateSecurityScheme);

            var securityRequirement = new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = JwtBearerDefaults.AuthenticationScheme
                        }
                    },
                    []
                },
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = NegotiateDefaults.AuthenticationScheme
                        }
                    },
                    []
                }
            };

            o.AddSecurityRequirement(securityRequirement);
        });

        return services;
    }
}
