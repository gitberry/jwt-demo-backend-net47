using Microsoft.IdentityModel.Tokens;
using Uzer;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace JWT
{
    public class helper
    {
        public static Object ValidateAndGenerateToken(
            string givenUserID,
            string givenUserPassword,
            List<MockUzer> givenUsers,
            string givenAPISecret,
            string givenIssuerSite,
            string givenClientSite,
            string givenTokenClaimName,
            DateTime givenTokenExpires
            )
        {
            MockUzer thisUzer = givenUsers.Find(z => z.uzer.ToUpper() == givenUserID.ToUpper());
            if (thisUzer != null)
            {
                if (thisUzer.hashedPassword == helper.HashPassword(givenUserPassword, thisUzer.hashseed))
                {
                    // the user is authenticated - let's generate a token and return it..
                    return GenerateToken(
                        givenAPISecret
                        , givenIssuerSite
                        , givenClientSite
                        , givenTokenClaimName
                        , givenTokenExpires);
                }
            }
            return null;
        }
          
        public static Object GenerateToken(
            string givenAPISecret,
            string givenIssuerSite,
            string givenClientSite,
            string givenTokenClaimName,
            DateTime givenTokenExpires
            )
        {
            var thisSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(givenAPISecret));
            var thisCredentials = new SigningCredentials(thisSecurityKey, SecurityAlgorithms.HmacSha256);

            //Create a List of Claims, Keep claims name short    
            var permClaims = new List<Claim>();
            //chr observation: I'm presuming that a GUID adds a bunch of randomness to the token - thus the signature won't betray the validating secret...
            permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            permClaims.Add(new Claim("valid", "1"));
            //permClaims.Add(new Claim("userid", "1")); // redacted to keep api minimal
            permClaims.Add(new Claim("name", givenTokenClaimName)); // our link to a user table somewhere

            //Create Security Token object by giving required parameters    
            var token = new JwtSecurityToken(
                            givenIssuerSite,
                            givenClientSite,
                            permClaims,
                            expires: givenTokenExpires,
                            signingCredentials: thisCredentials);
            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);
            return new { data = jwt_token };
        }
    
        public static bool TryRetrieveToken(HttpRequestMessage givenRequest, out string token)
        {
            token = null;
            IEnumerable<string> authzHeaders;
            if (!givenRequest.Headers.TryGetValues("Authorization", out authzHeaders) || authzHeaders.Count() > 1)
            {
                return false;
            }
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
            // next two lines are a kludge because the client is sending JSON instead of encoded string...
            var badhead = "{\"data\":\"";
            if (token.Substring(0,badhead.Length) == badhead ) { token = token.Substring(badhead.Length); token = token.Substring(0, token.Length - 2); }
            return true; 
        }

        public bool ValidateToken(HttpRequestMessage givenRequest, List<MockUzer> givenUsers, string givenSecret)
        {
            TokenValidationParameters theseParams = generateTokenValidationParameters(
                givenSecret, 
                AppConfig.Setting.JWTclientSite, 
                AppConfig.Setting.JWTapiSite, 
                true, 
                true);
            return ValidateHeaderToken(givenRequest, givenUsers, theseParams);
        }

        public bool ValidateHeaderToken(HttpRequestMessage givenRequest, List<MockUzer> givenUsers, TokenValidationParameters givenTokenValidationParameters) 
        {
            string requestHeaderJwtTokenJSON;
            if (!TryRetrieveToken(givenRequest, out requestHeaderJwtTokenJSON)) { return false; }

            SecurityToken unusedSecurityToken;
            JwtSecurityTokenHandler tmpJwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                ClaimsPrincipal result = tmpJwtSecurityTokenHandler.ValidateToken(requestHeaderJwtTokenJSON, givenTokenValidationParameters, out unusedSecurityToken);
                if ( result.Identity.IsAuthenticated ) {
                    // testing indicates that is also properly fails expired tokens so..
                    // the following is the belt accompanying the suspenders:
                    string claimExpiryText = result.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                    DateTime claimExpiry = ConvertFromUnixTimestamp(claimExpiryText); // new DateTime(0);
                    if ( claimExpiry >= DateTime.UtcNow)
                    {
                        // this would be the placed to check if user exists etc if specs indicate
                        return true; 
                    }
                }
            }
#if DEBUG
            catch (Exception ex)
            {
                var thisEX = ex;
#else
            catch 
            {
#endif
                return false;
            }
            return false;
        }

        public TokenValidationParameters generateTokenValidationParameters(
            string givenSecret, 
            string givenAudience,
            string givenIssuer,
            bool givenLifetime        ,    
            bool givenIssuerSigningKey
            )
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(givenSecret));
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                ValidAudience = givenAudience, 
                ValidIssuer = givenIssuer, 
                ValidateLifetime = givenLifetime, 
                ValidateIssuerSigningKey = givenIssuerSigningKey, 
                LifetimeValidator = this.LifetimeValidator,
                IssuerSigningKey = securityKey
            };
            return validationParameters;
        }

        public static DateTime ConvertFromUnixTimestamp(string givenTimestampText)
        {
            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            int timestamp = 0;
            int.TryParse(givenTimestampText, out timestamp);
            return origin.AddSeconds(timestamp); //
        }

        public bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (expires != null)
            {
                if (DateTime.UtcNow < expires) return true;
            }
            return false;
        }

        public static string HashPassword(string password, string salt)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                return Convert.ToBase64String(sha1.ComputeHash(Encoding.UTF8.GetBytes(salt + password)));
            }
        }

        // thanks for the reminder of how to use this: https://stackoverflow.com/questions/31908529/randomnumbergenerator-proper-usage
        public static string GenRandomSeed()
        {
            return Convert.ToBase64String(GenerateSaltNewInstance(42));
        }

        private static byte[] GenerateSaltNewInstance(int size)
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                var salt = new byte[size];
                generator.GetBytes(salt);
                return salt;
            }
        }
    }

}
