using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Domain.Users;
using Domain.Users.Errors;
using Shared;
using System.Linq;

namespace Application.User.Authenticate;

public class AuthenticateUserCommandHandler(IUserContext context, ITokenProvider tokenProvider)
    : ICommandHandler<AuthenticateUserCommand, string>
{
    public async Task<Result<string>> 
        Handle(AuthenticateUserCommand command, CancellationToken cancellationToken = default)
    {
        if (!context.IsSameDomain(command.Domain))
            return Result.Failure<string>(UserErrors.BadRequest("Domain", nameof(command.Username)));

        if (!context.IsUserActive(command.Username))
            return Result.Failure<string>(UserErrors.BadRequest("Username", nameof(command.Username)));

        var loginResult = Login.Create(command.Username);
        if (loginResult.IsFailure)
            return Result.Failure<string>(loginResult.Error);

        var groups = context.Groups.Select(g => g.Name).ToArray();
        var token = tokenProvider.Create(loginResult.Value, groups);
        return token;
    }
}
