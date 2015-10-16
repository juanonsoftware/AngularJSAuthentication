using System.Security.Claims;
using System.Threading.Tasks;
using Owin.Security.Providers.GitHub;

namespace WebApiExternalAuth.Providers
{
    public class GitHubCustomAuthenticationProvider : GitHubAuthenticationProvider
    {
        public override Task Authenticated(GitHubAuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim(Claims.ExternalAccessToken, context.AccessToken));
            context.Identity.AddClaim(new Claim(Claims.ExternalName, context.Name));

            return base.Authenticated(context);
        }
    }
}