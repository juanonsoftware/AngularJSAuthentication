using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Owin;
using System.Web.Http;
using WebApiExternalAuth.App_Start;

[assembly: OwinStartup(typeof(WebApiExternalAuth.Startup))]

namespace WebApiExternalAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();

            app.UseCors(CorsOptions.AllowAll);

            WebApiConfig.Register(config);

            app.ConfigureSecurity();

            app.UseWebApi(config);
        }
    }
}
