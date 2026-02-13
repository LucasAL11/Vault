using System.Reflection;
using Api.Extensions;
using Application;
using Infrastructure;
using Microsoft.AspNetCore.Server.HttpSys;
using Serilog;

namespace Api;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.WebHost.UseHttpSys(options =>
        {
            options.Authentication.Schemes = 
                AuthenticationSchemes.Negotiate 
                | AuthenticationSchemes.NTLM ;
            
            options.Authentication.AllowAnonymous = false;
        });
        
        builder.Host.UseSerilog((context, loggerConfiguration) 
            => loggerConfiguration.ReadFrom.Configuration(context.Configuration));
        
        builder.Services.AddControllers();

        builder.Services
            .AddApplication()
            .AddPresentation()
            .AddInfrastructure(builder.Configuration);
        
        builder
            .Services
            .AddSwaggerGenWithAuth();
        
        builder.Services.AddEndpoints(Assembly.GetExecutingAssembly());

        var app = builder.Build();
        app.MapEndpoints();
        
        if (app.Environment.IsDevelopment())
        {
            app.UseSwaggerWithUi();
        }

        app.UseSerilogRequestLogging();
        app.UseAuthentication();
        app.UseAuthorization();
        
        app.MapControllers();

        app.Run();
    }
}
