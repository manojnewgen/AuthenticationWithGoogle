﻿using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthenticationWithGoogle.Models;

public class User
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";

    public ClaimsPrincipal ToClaimsPrincipal() => new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
    {
            new Claim(ClaimTypes.Name, Username),
            new Claim(ClaimTypes.Hash, Password)
    }, "BlazorSchool"));

    public static User FromClaimsPrincipal(ClaimsPrincipal principal) => new User
    {
        Username = principal.FindFirst(ClaimTypes.Name)?.Value ?? "",
        Password = principal.FindFirst(ClaimTypes.Hash)?.Value ?? ""
    };

    public static User? FromGoogleJwt(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        if (tokenHandler.CanReadToken(token))
        {
            var jwtSecurityToken = tokenHandler.ReadJwtToken(token);

            return new User
            {
                Username = jwtSecurityToken.Claims.First(c => c.Type == "name").Value,
                Password = ""
            };
        }

        return null;
    }
}
