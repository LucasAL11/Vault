using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging;
using Application.Abstractions.Messaging.Handlers;
using Application.Test;
using Microsoft.AspNetCore.Mvc;
using Shared;

namespace Api.Endpoints.TestEnpoint;

public class test : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
       builder.MapGet("/test", async ([FromServices] IMessageDispatcher sender, CancellationToken cancellationToken) =>
       {
           var command = new TestApplicationCommunication();
           
           Result<string> result = await sender.Send(command, cancellationToken);

           return result.Match(Results.Ok, CustomResults.Problem);
       });
    }
}