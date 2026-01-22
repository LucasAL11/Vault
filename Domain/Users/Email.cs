using Domain.Users.Errors;
using Shared;

namespace Domain.Users;

public class Email
{
    public string Value { get;}

    private Email(string value)
    {
        Value = value;
    }
    
    public static Result<Email> Create(string serial)
    {
        if (string.IsNullOrEmpty(serial) || serial.Length != 32)
            return Result.Failure<Email>(UserErrors.BadRequest(nameof(Email), nameof(serial)));

        return Result.Success(new Email(serial));
    }
}