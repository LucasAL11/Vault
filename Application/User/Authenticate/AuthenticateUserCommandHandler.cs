using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.User.LocalAuth;
using Domain.Users;
using Domain.Users.Errors;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.User.Authenticate;

internal sealed class AuthenticateUserCommandHandler(
    IUserContext context,
    ITokenProvider tokenProvider,
    IApplicationDbContext dbContext)
    : ICommandHandler<AuthenticateUserCommand, string>
{
    public async Task<Result<string>> Handle(
        AuthenticateUserCommand command, CancellationToken cancellationToken = default)
    {
        // Se domain veio preenchido → AD auth (com senha validada contra o AD)
        if (!string.IsNullOrWhiteSpace(command.Domain))
            return HandleAdAuth(command);

        // Senão → local auth (senha contra a tabela local_users)
        return await HandleLocalAuthAsync(command, cancellationToken);
    }

    private async Task<Result<string>> HandleLocalAuthAsync(
        AuthenticateUserCommand command, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(command.Password))
            return Result.Failure<string>(UserErrors.BadRequest("Password", "Password is required for local authentication."));

        var users = await dbContext.Users.ToListAsync(cancellationToken);
        var user = users.FirstOrDefault(u =>
            string.Equals(u.UserName.UserName, command.Username, StringComparison.OrdinalIgnoreCase));

        if (user is null || !LocalPasswordHasher.Verify(command.Password!, user.PasswordHash))
            return Result.Failure<string>(UserErrors.BadRequest("Credentials", "Invalid username or password."));

        var loginResult = Login.Create(user.UserName.UserName);
        if (loginResult.IsFailure)
            return Result.Failure<string>(loginResult.Error);

        var token = tokenProvider.Create(loginResult.Value, groups: null);
        return token;
    }

    private Result<string> HandleAdAuth(AuthenticateUserCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Password))
            return Result.Failure<string>(UserErrors.BadRequest("Password", "Password is required for AD authentication."));

        if (!context.IsSameDomain(command.Domain!))
            return Result.Failure<string>(UserErrors.BadRequest("Domain", "Domain does not match the server domain."));

        if (!context.IsUserActive(command.Username))
            return Result.Failure<string>(UserErrors.BadRequest("Username", "User not found or inactive in Active Directory."));

        // Valida a senha contra o AD via PrincipalContext.ValidateCredentials
        if (!context.ValidateCredentials(command.Username, command.Password))
            return Result.Failure<string>(UserErrors.BadRequest("Credentials", "Invalid username or password."));

        var loginResult = Login.Create(command.Username);
        if (loginResult.IsFailure)
            return Result.Failure<string>(loginResult.Error);

        var groups = context.GetGroupsForUser(command.Username).Select(g => g.Name).ToArray();
        var token = tokenProvider.Create(loginResult.Value, groups);
        return token;
    }
}
