using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.User;
using Shared;

namespace Api.Endpoints.Users;

public class Authenticate : IEndpoint
{
    private record Request(
        string Username,
        string Domain
        );
    
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/users", async (Request request, IMessageDispatcher sender) =>
        {
            var command = new AuthenticateUserCommand(request.Username, request.Domain);
            Result<string> result = await sender.Send(command);
            
            return result.Match(Results.Ok, CustomResults.Problem);
        });
    }
}