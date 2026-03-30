using System.Reflection;
using System.Threading.RateLimiting;
using Api.Extensions;
using Api.Logging;
using Api.Middleware;
using Api.Security;
using Application;
using Domain.KillSwitch;
using Infrastructure;
using Microsoft.AspNetCore.Authorization.Policy;
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
        builder.Services.Configure<AuthChallengeOptions>(builder.Configuration.GetSection("AuthChallenge"));
        builder.Services.Configure<CorsPolicyOptions>(builder.Configuration.GetSection("Cors"));
        builder.Services.Configure<SecurityHeadersOptions>(builder.Configuration.GetSection("SecurityHeaders"));
        builder.Services.Configure<RateLimitingOptions>(builder.Configuration.GetSection("RateLimiting"));
        builder.Services.AddSingleton<KillSwitchState>();
        builder.Services.AddScoped<KillSwitchMiddleware>();
        builder.Services.AddTransient<SecurityHeadersMiddleware>();
        builder.Services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, StructuredAuthorizationResultHandler>();

        builder.Services.AddControllers();
        var corsOptions = builder.Configuration.GetSection("Cors").Get<CorsPolicyOptions>() ?? new CorsPolicyOptions();
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("ApiCors", policy =>
            {
                if (corsOptions.AllowedOrigins.Length > 0)
                {
                    policy.WithOrigins(corsOptions.AllowedOrigins);
                }
                else if (builder.Environment.IsDevelopment())
                {
                    // In development, allow any origin (Chrome extensions, localhost, etc.)
                    policy.AllowAnyOrigin();
                }

                policy.WithMethods(corsOptions.AllowedMethods);
                policy.WithHeaders(corsOptions.AllowedHeaders);

                if (corsOptions.ExposedHeaders.Length > 0)
                {
                    policy.WithExposedHeaders(corsOptions.ExposedHeaders);
                }

                if (corsOptions.AllowCredentials && corsOptions.AllowedOrigins.Length > 0)
                {
                    policy.AllowCredentials();
                }
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
}
