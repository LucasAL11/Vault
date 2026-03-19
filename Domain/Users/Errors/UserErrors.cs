using Shared;

namespace Domain.Users.Errors;

public static class UserErrors
{
    public static Error BadRequest(string property, string field)
        => new($"{property}.BadRequest", $"{field} value is invalid.", ErrorType.BadRequest);
}