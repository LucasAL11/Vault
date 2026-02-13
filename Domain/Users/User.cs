using Domain.Users.Errors;
using Shared;

namespace Domain.Users;

public class User
{
    public int Id { get; set; }
    public Login UserName { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string PasswordHash { get; set; }
}

public class Login
{
    public string UserName { get; }
    private Login(string username)
    {
        UserName = username;
    }

    public static Result<Login> Create(string username)
    {
        if (string.IsNullOrEmpty(username))
        {
            return Result.Failure<Login>(UserErrors.BadRequest("username", nameof(username)));
        }

        return Result.Success(new Login(username));
    }
}
