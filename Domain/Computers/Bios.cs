using Domain.Computers.Errors;
using Shared;

namespace Domain.Computers;

public class Bios
{
    public string Serial { get; }

    private Bios(string serial)
    {
        Serial = serial;
    }

    public static Result<Bios> Create(string serial)
    {
        if (string.IsNullOrEmpty(serial) || serial.Length != 32)
            return Result.Failure<Bios>(ComputerErrors.BadRequest());

        return Result.Success(new Bios(serial));
    }
    
    public override string ToString() => Serial;
}