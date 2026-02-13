using Application.Authentication;

namespace Api.Endpoints.Users;

public class Login : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapGet("/users/{id}", async (IUserContext userContext, string id) => 
        {
            
             return userContext.Identity;
        })
            .RequireAuthorization("AdGroup:NomeDoGrupo");
    }
}