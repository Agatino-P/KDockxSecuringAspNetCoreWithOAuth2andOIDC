using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews()
    .AddJsonOptions(configure => 
        configure.JsonSerializerOptions.PropertyNamingPolicy = null);

// create an HttpClient used for accessing the API
builder.Services.AddHttpClient("APIClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ImageGalleryAPIRoot"]);
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
    options.SignedOutRedirectUri= builder.Configuration["KeyCloack:SignedOutRedirectUri"]!;
    //options.CallbackPath = new PathString("signin-oidc");
    options.SaveTokens = true;
    //options.GetClaimsFromUserInfoEndpoint = true;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username" // or "name"
    };
    options.Events.OnTokenValidated = context =>
    {
        var nameClaimType = context.Principal.Identity.Name; // should be "david"
        Console.WriteLine("User.Identity.Name from OnTokenValidated: " + nameClaimType);

        foreach (var claim in context.Principal.Claims)
        {
            Console.WriteLine($"Claim: {claim.Type} = {claim.Value}");
        }

        return Task.CompletedTask;
    };
    options.Events.OnMessageReceived = context =>
    {
        Console.WriteLine("OIDC message received.");
        return Task.CompletedTask;
    };

});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Gallery}/{action=Index}/{id?}");

app.Run();
