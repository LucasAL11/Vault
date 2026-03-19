using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Authentication;
using Domain.Users;
using Infrastructure.Authentication;
using Infrastructure.Authentication.Jwt;
using Microsoft.Extensions.Options;
using Xunit;

namespace Infrastructure.Tests;

public sealed class JwtTokenProviderGroupClaimsTests
{
    [Fact]
    public void Create_WithGroups_ShouldEmitRoleAndGroupsClaims()
    {
        var provider = CreateProvider();
        var login = Login.Create("lucas.luna").Value;

        var jwt = provider.Create(login, new[] { "Admins", "Finance" });
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);

        Assert.Contains(token.Claims, c => c.Type == ClaimTypes.Role && c.Value == "Admins");
        Assert.Contains(token.Claims, c => c.Type == ClaimTypes.Role && c.Value == "Finance");
        Assert.Contains(token.Claims, c => c.Type == "groups" && c.Value == "Admins");
        Assert.Contains(token.Claims, c => c.Type == "groups" && c.Value == "Finance");
    }

    private static JwtTokenProvider CreateProvider()
    {
        var options = Options.Create(new JwtOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            Secret = "01234567890123456789012345678901",
            ExpirationMinutes = 60
        });

        return new JwtTokenProvider(options, new SystemDateTimeProvider());
    }
}
