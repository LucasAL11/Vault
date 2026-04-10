using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.User.Register;
using Shared;

namespace Api.Endpoints.Users;

public sealed class RegisterUser : IEndpoint
{
    private record Request(string Username, string Password, string FirstName, string LastName);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/users/register", async (Request request, IMessageDispatcher sender) =>
        {
            var command = new RegisterUserCommand(request.Username, request.Password, request.FirstName, request.LastName);
            Result<int> result = await sender.Send(command);

            return result.Match(id => Results.Created($"/users/{id}", new { id }), CustomResults.Problem);
        });
    }
}
