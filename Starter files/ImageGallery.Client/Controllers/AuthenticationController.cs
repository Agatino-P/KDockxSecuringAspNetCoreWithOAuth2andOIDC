using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace ImageGallery.Client.Controllers;
public class AuthenticationController : Controller
{
    [Authorize]
    public async Task Logout()
    {
        //this clears the local cookie but does not logout from the identity provider on its own
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

         //Redirects to the end session endpoint on the identity provider linked to scheme "OpenIdConnectDefaults.AuthenticationScheme" (i.e.: oidc")
        //so it can clear its own session/cookie
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
    }
}
