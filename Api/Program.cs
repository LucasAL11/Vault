using System.Reflection;
using System.Threading.RateLimiting;
using Api.Extensions;
using Api.Logging;
using Api.Middleware;
using Api.Security;
using Application;
using Domain.KillSwitch;
using Infrastructure;
using Microsoft.AspNetCore.RateLimiting;
using Serilog;

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
        builder.Services.AddSingleton<KillSwitchState>();
        builder.Services.AddScoped<KillSwitchMiddleware>();

        builder.Services.AddControllers();
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.AddPolicy("SecretReadPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.User.Identity?.Name ?? "anonymous"}|{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 20,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        AutoReplenishment = true
                    }));

            options.AddPolicy("SecretAuditReadPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{httpContext.User.Identity?.Name ?? "anonymous"}|{httpContext.Connection.RemoteIpAddress}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 10,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        AutoReplenishment = true
                    }));

            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = "60";
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
                .WithGroupName("v1"));

        // Backward compatibility for existing clients while moving to versioned routes.
        app.MapEndpoints(
            app.MapGroup(string.Empty)
                .WithGroupName("legacy")
                .ExcludeFromDescription());

        if (app.Environment.IsDevelopment())
        {
            app.UseSwaggerWithUi();
        }

        app.UseExceptionHandler();

        app.UseMiddleware<RequestContextLoggingMiddleware>();

        app.UseSerilogRequestLogging(options =>
        {
            options.MessageTemplate =
                "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms | TraceId={TraceId} | QueryMasked={RequestQueryMasked} | HeadersMasked={RequestHeadersMasked}";

            options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                diagnosticContext.Set("TraceId", httpContext.TraceIdentifier);
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
}
