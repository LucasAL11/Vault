namespace Domain.Computers;

public sealed record CpuId(string Value)
{
    public override string ToString() => Value;
}