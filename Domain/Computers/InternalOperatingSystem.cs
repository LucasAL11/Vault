namespace Domain.Computers;

public sealed record InternalOperatingSystem(string Value)
{
    public override string ToString() => Value;
}