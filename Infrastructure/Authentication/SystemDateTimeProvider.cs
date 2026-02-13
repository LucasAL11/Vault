using Shared;

namespace Infrastructure.Authentication;

public sealed class SystemDateTimeProvider : IDateTimeProvider
{
    public DateTime UtcNow => DateTime.Now;
}
