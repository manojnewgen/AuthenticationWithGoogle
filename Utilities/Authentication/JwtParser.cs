﻿using System.Security.Claims;
using System.Text.Json;

namespace AuthenticationWithGoogle.Authentication
{
    public static class JwtParser
    {

        public static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var claims= new List<Claim>();
            var payload= jwt.Split('.')[1].Trim();
            var jsonBytes= ParseBase64WithoutPadding(payload);
            var keyValuePairs= JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);
            ExtractRoleFromJWT(claims, keyValuePairs);
            claims.AddRange(keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString())));
            return claims;

        }
        private static void ExtractRoleFromJWT(List<Claim> claims, Dictionary<string, object> keyValuePairs)
        {
            keyValuePairs.TryGetValue(ClaimTypes.Role, out object roles);
            if (roles is not null)
            {
                var parsedRole = roles.ToString().Trim().TrimStart('[').TrimEnd(']').Split(',');
                if (parsedRole.Length > 1)
                {
                    foreach (var parseRole in parsedRole)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, parseRole.Trim('"')));
                    }
                }
                else
                {
                    claims.Add(new Claim(ClaimTypes.Role, parsedRole[0]));
                }
                keyValuePairs.Remove(ClaimTypes.Role);
              

            }
        }


        private static byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}
