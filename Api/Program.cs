using System.Reflection;
using System.Threading.RateLimiting;
using Api.Extensions;
using Api.Logging;
using Api.Middleware;
using Api.Endpoints.Vault.Secret;
using Api.Security;
using Application;
using Application.Vault.Secrets;
using Domain.KillSwitch;
using Infrastructure;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.RateLimiting;
using Serilog;
using System.Diagnostics;

namespace Api;

public partial class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Host.UseSerilog((context, loggerConfiguration)
            => loggerConfiguration.ReadFrom.Configuration(context.Configuration));

        builder.Services.Configure<KillSwitchOptions>(builder.Configuration.GetSection("KillSwitch"));
        builder.Services.AddOptions<AuthChallengeOptions>()
            .Bind(builder.Configuration.GetSection("AuthChallenge"))
            .Validate(
                static options => options.ClientSecrets.Any(entry => !string.IsNullOrWhiteSpace(entry.Value)),
                "AuthChallenge:ClientSecrets must include at least one non-empty secret value.")
            .ValidateOnStart();
        builder.Services.Configure<SecretVersionRetentionOptions>(builder.Configuration.GetSection("SecretVersionRetention"));
        builder.Services.Configure<CorsPolicyOptions>(builder.Configuration.GetSection("Cors"));
        builder.Services.Configure<SecurityHeadersOptions>(builder.Configuration.GetSection("SecurityHeaders"));
        builder.Services.Configure<RateLimitingOptions>(builder.Configuration.GetSection("RateLimiting"));
        builder.Services.AddSingleton<KillSwitchState>();
        builder.Services.AddScoped<KillSwitchMiddleware>();
        builder.Services.AddTransient<SecurityHeadersMiddleware>();
        builder.Services.AddScoped<ISecretAccessAuthorizer, SecretAccessAuthorizer>();
        builder.Services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, StructuredAuthorizationResultHandler>();

        builder.Services.AddControllers();
        var corsOptions = (builder.Configuration.GetSection("Cors").Get<CorsPolicyOptions>() ?? new CorsPolicyOptions()).GetNormalized();
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("ApiCors", policy =>
            {
                ConfigureCorsPolicy(policy, corsOptions);
            });
        });

        builder.Services.AddRateLimiter(options =>
        {
            var rateLimitingOptions = builder.Configuration.GetSection("RateLimiting").Get<RateLimitingOptions>() ?? new RateLimitingOptions();
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.AddPolicy("SecretReadPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.User.Identity?.Name ?? "anonymous"}|{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.SecretRead)));

            options.AddPolicy("SecretWritePolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.User.Identity?.Name ?? "anonymous"}|{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.SecretWrite)));

            options.AddPolicy("SecretAuditReadPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.User.Identity?.Name ?? "anonymous"}|{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.SecretAuditRead)));

            options.AddPolicy("AuthChallengePolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.AuthChallenge)));

            options.AddPolicy("AuthChallengeVerifyPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.AuthChallengeVerify)));

            options.AddPolicy("AuthChallengeRespondPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.AuthChallengeRespond)));

            options.AddPolicy("OpsSensitivePolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.User.Identity?.Name ?? "anonymous"}|{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => BuildFixedWindowOptions(rateLimitingOptions.OpsSensitive)));

            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = Math.Max(1, rateLimitingOptions.RetryAfterSeconds).ToString();
                await context.HttpContext.Response.WriteAsJsonAsync(new
                {
                    message = "Too many requests. Please try again later."
                }, cancellationToken);
            };
        });

        builder.Services
            .AddApplication()
            .AddPresentation()
            .AddInfrastructure(builder.Configuration);

        builder
            .Services
            .AddSwaggerGenWithAuth();

        builder.Services.AddEndpoints(Assembly.GetExecutingAssembly());

        var app = builder.Build();

        app.MapEndpoints(
            app.MapGroup("/api/v1")
                .WithGroupName("v1")
                .WithApiVersionHeader("v1"));

        // Backward compatibility for existing clients while moving to versioned routes.
        app.MapEndpoints(
            app.MapGroup(string.Empty)
                .WithGroupName("legacy")
                .ExcludeFromDescription());

        if (app.Environment.IsDevelopment())
        {
            app.UseSwaggerWithUi();
        }
        else
        {
            app.UseHsts();
        }

        app.UseExceptionHandler();

        app.UseCors("ApiCors");
        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseMiddleware<RequestContextLoggingMiddleware>();

        app.UseSerilogRequestLogging(options =>
        {
            options.MessageTemplate =
                "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms | TraceId={TraceId} | CorrelationId={CorrelationId} | SpanId={SpanId} | QueryMasked={RequestQueryMasked} | HeadersMasked={RequestHeadersMasked}";

            options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                var correlationId = httpContext.Items.TryGetValue(RequestContextLoggingMiddleware.CorrelationIdItemName, out var value)
                    ? value?.ToString() ?? httpContext.TraceIdentifier
                    : httpContext.TraceIdentifier;

                diagnosticContext.Set("TraceId", httpContext.TraceIdentifier);
                diagnosticContext.Set("CorrelationId", correlationId);
                diagnosticContext.Set("SpanId", Activity.Current?.SpanId.ToString() ?? string.Empty);
                diagnosticContext.Set(
                    "RequestHeadersMasked",
                    SensitiveDataMasker.MaskHeaders(httpContext.Request.Headers),
                    destructureObjects: true);

                diagnosticContext.Set(
                    "RequestQueryMasked",
                    SensitiveDataMasker.MaskQuery(httpContext.Request.Query),
                    destructureObjects: true);
            };
        });
        app.UseMiddleware<SecurityMetricsMiddleware>();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseMiddleware<KillSwitchMiddleware>();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }

    private static FixedWindowRateLimiterOptions BuildFixedWindowOptions(FixedWindowPolicyOptions settings)
    {
        return new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, settings.PermitLimit),
            Window = TimeSpan.FromSeconds(Math.Max(1, settings.WindowSeconds)),
            QueueLimit = Math.Max(0, settings.QueueLimit),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true
        };
    }

    private static void ConfigureCorsPolicy(CorsPolicyBuilder policy, CorsPolicyOptions options)
    {
        if (options.AllowedOrigins.Length == 0)
        {
            return;
        }

        var allowAnyOrigin = options.AllowedOrigins.Length == 1 &&
                             string.Equals(options.AllowedOrigins[0], "*", StringComparison.Ordinal);

        if (allowAnyOrigin && options.AllowCredentials)
        {
            throw new InvalidOperationException("Cors configuration is invalid: AllowCredentials cannot be true when AllowedOrigins contains '*'.");
        }

        if (allowAnyOrigin)
        {
            policy.AllowAnyOrigin();
        }
        else
        {
            policy.WithOrigins(options.AllowedOrigins);
        }

        if (options.AllowedMethods.Length == 1 && string.Equals(options.AllowedMethods[0], "*", StringComparison.Ordinal))
        {
            policy.AllowAnyMethod();
        }
        else
        {
            policy.WithMethods(options.AllowedMethods);
        }

        if (options.AllowedHeaders.Length == 1 && string.Equals(options.AllowedHeaders[0], "*", StringComparison.Ordinal))
        {
            policy.AllowAnyHeader();
        }
        else
        {
            policy.WithHeaders(options.AllowedHeaders);
        }

        if (options.ExposedHeaders.Length > 0)
        {
            policy.WithExposedHeaders(options.ExposedHeaders);
        }

        if (options.AllowCredentials)
        {
            policy.AllowCredentials();
        }

        if (options.PreflightMaxAgeSeconds > 0)
        {
            policy.SetPreflightMaxAge(TimeSpan.FromSeconds(options.PreflightMaxAgeSeconds));
        }
    }
}
