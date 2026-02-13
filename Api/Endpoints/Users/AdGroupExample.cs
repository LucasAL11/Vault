namespace Api.Endpoints.Users;

public sealed class AdGroupExample : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/users/ad-group-example", () => Results.Ok(new { Status = "ok" }))
            .RequireAuthorization("AdGroup:vendasss");
    }
}
