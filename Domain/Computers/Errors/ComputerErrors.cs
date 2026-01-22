using Shared;

namespace Domain.Computers.Errors;

public static class ComputerErrors
{
    public static Error BadRequest()
        => new("Serial.BadRequest", "Serial value is invalid.", ErrorType.BadRequest);
}