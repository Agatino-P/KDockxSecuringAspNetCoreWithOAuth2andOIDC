using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Text.Json;

namespace ImageGallery.API.ClaimsHandling;
public class RoleClaimsTransformer : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = (ClaimsIdentity)principal.Identity!;
        var roleClaim = identity.FindFirst("role");
        if (roleClaim != null && roleClaim.Value.StartsWith("["))
        {
            var roles = JsonSerializer.Deserialize<string[]>(roleClaim.Value);
            foreach (var role in roles ?? Array.Empty<string>())
            {
                identity.AddClaim(new Claim(identity.RoleClaimType, role));
            }
        }

        return Task.FromResult(principal);
    }
}
