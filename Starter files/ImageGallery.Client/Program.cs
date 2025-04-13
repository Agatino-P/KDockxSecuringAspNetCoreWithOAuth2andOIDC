using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews()
    .AddJsonOptions(configure =>
        configure.JsonSerializerOptions.PropertyNamingPolicy = null);

JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

// create an HttpClient used for accessing the API
builder.Services.AddHttpClient("APIClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ImageGalleryAPIRoot"]!);
    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
});


builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.Authority = builder.Configuration["KeyCloack:Authority"];
    options.ClientId = builder.Configuration["KeyCloack:ClientId"];
    options.ClientSecret = builder.Configuration["KeyCloack:ClientSecret"];
    options.ResponseType = "code";
    options.SignedOutRedirectUri = builder.Configuration["KeyCloack:SignedOutRedirectUri"]!;
    options.SaveTokens = true;
    options.Scope.Add("openid");   // Required for OpenID Connect

    options.GetClaimsFromUserInfoEndpoint = true;
    options.ClaimActions.Remove("aud");
    options.ClaimActions.DeleteClaim("sid");
    options.ClaimActions.DeleteClaim("idp");
    options.ClaimActions.MapJsonSubKey("role", "realm_access", "roles");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username", // or "name"
        RoleClaimType = "role"
    };

    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = context =>
        {
            ClaimsIdentity? identity = context?.Principal?.Identity as ClaimsIdentity;
            if (identity is null)
            {
                return Task.CompletedTask;
            }

            string? accessToken = context?.TokenEndpointResponse?.AccessToken;
            if (accessToken is null)
            {
                return Task.CompletedTask;
            }

            identity.AddClaim(new Claim("access_token", accessToken));

            // Parse access token as JWT
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(accessToken);

            // Extract realm roles
            if (jwt.Payload.TryGetValue("realm_access", out var realmAccessObj) &&
                realmAccessObj is JsonElement realmAccess &&
                realmAccess.TryGetProperty("roles", out var roles))
            {
                foreach (JsonElement role in roles.EnumerateArray())
                {
                    identity.AddClaim(new Claim("role", role.GetString() ?? ""));
                }
            }

            // Extract client roles from resource_access.account
            if (jwt.Payload.TryGetValue("resource_access", out var resourceAccessObj) &&
                resourceAccessObj is JsonElement resourceAccess &&
                resourceAccess.TryGetProperty("account", out var account) &&
                account.TryGetProperty("roles", out var accountRoles))
            {
                foreach (var role in accountRoles.EnumerateArray())
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role.GetString() ?? ""));
                }
            }
            return Task.CompletedTask;
        }
    };


});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    if (!string.IsNullOrEmpty(authHeader))
    {
        Console.WriteLine($"Authorization Header: {authHeader}");
    }

    await next();
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Gallery}/{action=Index}/{id?}");

app.Run();
