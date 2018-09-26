using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Http.Controllers;
using System.IdentityModel.Tokens;
using Rantai.Common.DTO;

namespace Rantai.WeApi.AuthModule
{
    public class AuthenticationModule
    {
        private const string communicationKey = "GQDstc21ewfffffffffffFiwDffVvVBrk";
        SecurityKey signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(communicationKey));      
        public string GenerateTokenForUser(UserDto user)
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(communicationKey));
            var now = DateTime.UtcNow;
            var signingCredentials = new SigningCredentials(signingKey,
               SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            var claimsIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Email),
                new Claim("role",user.UserType.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim("fname", user.FirstName),
                 new Claim("lname", user.LastName),
                new Claim("permissions", user.Permissions),
                //new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                //new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                //new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                //new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                //new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                //new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            }, "Custom");

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Audience = "http://www.example.com",
                Issuer = "self",
                Subject = claimsIdentity,
                SigningCredentials = signingCredentials,
                Expires = DateTime.Now.AddDays(1),
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var plainToken = tokenHandler.CreateToken(securityTokenDescriptor);
            var signedAndEncodedToken = tokenHandler.WriteToken(plainToken);

            return signedAndEncodedToken;

        }
       
        public JwtSecurityToken GenerateUserClaimFromJWT(string authToken)
        {

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                      {
                    "http://www.example.com",
                      },

                ValidIssuers = new string[]
                  {
                      "self",
                  },
                IssuerSigningKey = signingKey
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            SecurityToken validatedToken;

            try
            {

                tokenHandler.ValidateToken(authToken, tokenValidationParameters, out validatedToken);
            }
            catch (Exception ex)
            {
                return null;

            }

            return validatedToken as JwtSecurityToken;

        }

        public CustomPrincipal PopulateUserIdentity(JwtSecurityToken userPayloadToken)
        {
            string name = ((userPayloadToken)).Claims.FirstOrDefault(m => m.Type == "unique_name").Value;
            string userId = ((userPayloadToken)).Claims.FirstOrDefault(m => m.Type == "nameid").Value;
            string role = ((userPayloadToken)).Claims.FirstOrDefault(m => m.Type == "role").Value;
            string fname = ((userPayloadToken)).Claims.FirstOrDefault(m => m.Type == "fname").Value;
            string lname = ((userPayloadToken)).Claims.FirstOrDefault(m => m.Type == "lname").Value;
            string permissions = ((userPayloadToken)).Claims.FirstOrDefault(m => m.Type == "permissions").Value;
            
            CustomPrincipal newUser = new CustomPrincipal(name);
            newUser.UserId = Convert.ToInt32(userId);
            newUser.FirstName = fname;
            newUser.LastName = lname;
            newUser.Type = Convert.ToInt32(role);
            newUser.Permissions = permissions;
            return newUser;

        }

       
    }
}