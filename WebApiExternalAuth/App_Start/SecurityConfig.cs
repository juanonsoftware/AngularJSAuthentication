using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth;
using Owin;
using Owin.Security.Providers.GitHub;
using WebApiExternalAuth.Providers;

namespace WebApiExternalAuth.App_Start
{
    public static class SecurityConfig
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        public static void ConfigureSecurity(this IAppBuilder app)
        {
            //use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();

            app.UseOAuthBearerAuthentication(OAuthBearerOptions);

            app.UseGitHubAuthentication(new GitHubAuthenticationOptions()
            {
                ClientId = "78e903a27192ee724f5b",
                ClientSecret = "09aaed1ef94fda54c1430bf8b58f51b8e94733d9",
                Provider = new GitHubCustomAuthenticationProvider()
            });
        }
    }
}