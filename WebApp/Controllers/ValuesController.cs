using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static JWT.helper;
using System.Web.Http.Cors;
using System.Text.Json;
using Uzer;
using System.Web.Http.Description;


namespace WebApp.Controllers
{
    public class ValuesController : ApiController
    {
        // I have a tendency to use alternate spellings to avoid name clash with framework-names.
        // (avoiding past debugging trauma - plus alternate spellings are WAY easier to search for in code ha ha!) 
        [Route("API/authenikait")]
        [HttpGet]
        public Object authenikait(string username, string password)
        {
            if (IsValidJWTToken())
            {
                // this is an odd situation - and obviously the client code (or user) is doing something that we really don't think is valid 
                // (ie they're trying to be authenticated WHILE they're carrying a valid token
                // unless the use case changes - this code will throw them an esoteric error (teapot seems not to be available awww)
                throw new HttpResponseException(HttpStatusCode.ExpectationFailed);     //return null; // null is simple but does not inform client...
            }
            else
            {
                var result = JWT.helper.ValidateAndGenerateToken(
                      username
                    , password
                    , Uzer.helper.GimmeMockUzers()
                    , AppConfig.Setting.JWTsigningSecret
                    , AppConfig.Setting.JWTapiSite
                    , AppConfig.Setting.JWTclientSite
                    , username
                    , DateTime.UtcNow.AddMinutes(AppConfig.Setting.JWTMinutesToLive)
                    );
                if (result != null)
                { 
                    return result; 
                }
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);     //return null; // null is simple but does not inform client...
        }

        [Route("API/funnysongs")]
        [HttpGet]
        public Object[] FunnySongs(int recordRequest)
        {
            object[] dataResult = null;
            if (IsValidJWTToken())
            {
                dataResult = FunnySongz.helper.GenerateXFunnySongsFromJSON(FunnySongz.helper.FunnySongsSON, recordRequest);
                return dataResult;
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);     //return null; // null is simple but does not inform client...
        }

        [Route("API/funnysong/{id}")]
        [HttpGet]
        public Object[] FunnySong(int id)
        {
            object[] dataResult = null;
            if (IsValidJWTToken())
            {
                dataResult = FunnySongz.helper.GetFunnySongByID(id); 
                return dataResult;
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);     //return null; // null is simple but does not inform client...
        }

        public bool IsValidJWTToken()
        {
            return (new JWT.helper().ValidateToken(Request, Uzer.helper.GimmeMockUzers(), AppConfig.Setting.JWTsigningSecret));
        }

#if DEBUG
        // this would only be appropriate in a dev/debug/testing environment..
        [HttpGet]
        public Object GenerateToken(string username, string password)
        {
            var result = JWT.helper.ValidateAndGenerateToken(
                     username
                   , password
                   , Uzer.helper.GimmeMockUzers()
                   , AppConfig.Setting.JWTsigningSecret
                   , AppConfig.Setting.JWTapiSite
                   , AppConfig.Setting.JWTclientSite
                   , username
                   , DateTime.UtcNow.AddMinutes(AppConfig.Setting.JWTMinutesToLive)
                   );
            if (result != null)
            {
                return result;
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);     //return null; // null is simple but does not inform client...
        }

        // avoiding leaving something in prod that hasn't been tested...
        // post didn't work on example client for some reason... probably a quirk of .net 4.7 to define form fields??
        [Route("API/authenticate")]
        [HttpPost]
        public Object Authenticate(string username, string password)
        {
            var result = JWT.helper.ValidateAndGenerateToken(
                     username
                   , password
                   , Uzer.helper.GimmeMockUzers()
                   , AppConfig.Setting.JWTsigningSecret
                   , AppConfig.Setting.JWTapiSite
                   , AppConfig.Setting.JWTclientSite
                   , username
                   , DateTime.UtcNow.AddMinutes(AppConfig.Setting.JWTMinutesToLive)
                   );
            if (result != null)
            {
                return result;
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);     //return null; // null is simple but does not inform client...
        }

        // avoiding unauthenticated access of data in prod
        [Route("API/ListAvailableWithoutValidation")]
        [HttpGet]
        public Object[] SomeData2(string param1, string param2)
        {
            return FunnySongz.helper.GenerateFunnySongsFromJSON(FunnySongz.helper.FunnySongsSON);
        }
#endif
    }
}

