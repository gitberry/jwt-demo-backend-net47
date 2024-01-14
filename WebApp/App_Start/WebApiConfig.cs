using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using Microsoft.Owin.Security.OAuth;

namespace WebApp
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // apply permissions for Cross Origin Resource Scripting - if specified - default prod is ""
            if (AppConfig.Setting.CORSorigin != "" )
            {
                var cors = new EnableCorsAttribute(AppConfig.Setting.CORSorigin, "*", "*");
                config.EnableCors(cors);
            }
            // so we can do JWT instead of whatever default MS IIS wants to do...
            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // Web API routes
            config.MapHttpAttributeRoutes();
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}/{id}", // project template was: routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
