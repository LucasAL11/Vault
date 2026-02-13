using Shared;

namespace Api.Endpoints.Users;

public sealed class TimeDebug : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/debug/time", (IDateTimeProvider dateTimeProvider) => Results.Ok(new
        {
            UtcNow = dateTimeProvider.UtcNow,
            LocalNow = dateTimeProvider.UtcNow.ToLocalTime()
        }));
    }
}
