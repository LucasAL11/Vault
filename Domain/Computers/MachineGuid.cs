namespace Domain.Computers;

public sealed record MachineGuid(string Value)
{
    public override string ToString() => Value;
}