using Domain.Computers.Errors;
using Shared;

namespace Domain.Computers;

public class Disk
{
    public string Serial { get; }

    private Disk(string serial)
    {
        Serial = serial;
    }

    public static Result<Disk> Create(string serial)
    {
        if (string.IsNullOrEmpty(serial) || serial.Length != 32)
            return Result.Failure<Disk>(ComputerErrors.BadRequest());

        return Result.Success(new Disk(serial));
    }
    
    public override string ToString() => Serial;
}