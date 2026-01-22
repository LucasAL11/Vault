using Shared;

namespace Domain.Users.Errors;

public class UserErrors
{
    public static Error BadRequest(string property, string field)
        => new("Serial.BadRequest", "Serial value is invalid.", ErrorType.BadRequest);
}