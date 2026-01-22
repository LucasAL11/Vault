namespace Domain.Computers;

public sealed record ComputerId(string Value)
{
    public override string ToString() => Value;
}