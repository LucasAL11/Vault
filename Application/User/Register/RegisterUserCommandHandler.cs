using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.User.LocalAuth;
using Domain.Users.Errors;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.User.Register;

public class RegisterUserCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<RegisterUserCommand, int>
{
    public async Task<Result<int>> Handle(RegisterUserCommand command, CancellationToken cancellationToken = default)
    {
        var loginResult = Domain.Users.Login.Create(command.Username);
        if (loginResult.IsFailure)
            return Result.Failure<int>(loginResult.Error);

        var existingUsers = await dbContext.Users.ToListAsync(cancellationToken);
        var alreadyExists = existingUsers.Any(u =>
            string.Equals(u.UserName.UserName, command.Username, StringComparison.OrdinalIgnoreCase));

        if (alreadyExists)
            return Result.Failure<int>(UserErrors.BadRequest("Username", "Username already taken."));

        var user = new Domain.Users.User
        {
            UserName = loginResult.Value,
            FirstName = command.FirstName,
            LastName = command.LastName,
            PasswordHash = LocalPasswordHasher.Hash(command.Password)
        };

        await dbContext.Users.AddAsync(user, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return Result.Success(user.Id);
    }
}
