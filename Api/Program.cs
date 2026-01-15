using System.Reflection;
using Api.Extensions;
using Application;
using Serilog;

namespace Api;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Host.UseSerilog((context, loggerConfiguration) 
            => loggerConfiguration.ReadFrom.Configuration(context.Configuration));
        
        builder.Services.AddControllers();
        
        builder.Services
            .AddApplication()
            .AddPresentation();
        
        builder.Services.AddSwaggerGenWithAuth();
        builder.Services.AddEndpoints(Assembly.GetExecutingAssembly());

        var app = builder.Build();
        app.MapEndpoints();
        
        if (app.Environment.IsDevelopment())
        {
            app.UseSwaggerWithUi();
        }

        app.UseSerilogRequestLogging();
        app.UseAuthorization();
        
        app.MapControllers();

        app.Run();
    }
}