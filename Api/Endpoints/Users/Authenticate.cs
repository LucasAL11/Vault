using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.User.Authenticate;
using Shared;

namespace Api.Endpoints.Users;

public sealed class Authenticate : IEndpoint
{
    private record Request(
        string Username,
        string? Domain = null,
        string? Password = null);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/users", async (Request request, IMessageDispatcher sender) =>
        {
            var command = new AuthenticateUserCommand(request.Username, request.Domain, request.Password);
            Result<string> result = await sender.Send(command);

            return result.Match(Results.Ok, CustomResults.Problem);
        });
    }
}