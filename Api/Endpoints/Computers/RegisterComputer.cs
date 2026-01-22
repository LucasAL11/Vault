using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Computers;
using Shared;

namespace Api.Endpoints.Computers;

public class RegisterComputer : IEndpoint
{
    public sealed class Request
    {
        public string Name { get; set; }
        public string CpuId { get; set; }
        public string BiosSerial { get; set; }
        public string DiskSerial { get; set; }
        public string OperatingSystem { get; set; }
        public string MachineGuid { get; set; }
    }
    
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("computers", async (Request request, IMessageDispatcher sender) =>
        {
            var command = new RegisterComputerCommand(
                request.Name,
                request.CpuId,
                request.BiosSerial,
                request.DiskSerial,
                request.OperatingSystem,
                request.MachineGuid);
            
            Result<string> result = await sender.Send(command);
            
             return result.Match(Results.Ok, CustomResults.Problem);
        });
    }
}