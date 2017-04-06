using AuthorizationServer.Api.Formats;
using AuthorizationServer.Api.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Configuration;
using System.Web.Http;

namespace AuthorizationServer.Api
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();

            // Web API routes
            config.MapHttpAttributeRoutes();
            
            ConfigureOAuth(app);
            
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            
            app.UseWebApi(config);

        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            int ticketTimespan;
            int.TryParse(ConfigurationManager.AppSettings["TicketLifeInMinutes"], out ticketTimespan);

            if (ticketTimespan == 0)
                ticketTimespan = 30;

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                //For Dev enviroment only (on production should be AllowInsecureHttp = false)
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth2/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(ticketTimespan),
                Provider = new CustomOAuthProvider(),
                AccessTokenFormat = new CustomJwtFormat(ConfigurationManager.AppSettings["issuer"])
            };

            // OAuth 2.0 Bearer Access Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);

        }
    }
}