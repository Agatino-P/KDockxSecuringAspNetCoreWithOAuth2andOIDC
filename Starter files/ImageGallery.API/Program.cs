using ImageGallery.API.ClaimsHandling;
using ImageGallery.API.DbContexts;
using ImageGallery.API.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<IClaimsTransformation, RoleClaimsTransformer>();

// Optionally clear default claim mappings
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

// Add JWT Bearer Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["KeyCloack:Authority"];
        options.Audience = builder.Configuration["KeyCloack:Audience"];
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,  // Validate issuer of the token
            ValidateAudience = true, // Validate audience of the token
            ValidateLifetime = true, // Validate token expiry
            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", // <-- set this to the correct role claim type
            NameClaimType = "preferred_username", // You can use this for the username in the token
            ValidAudiences = new[] { builder.Configuration["KeyCloack:Audience"], "account" },

            ClockSkew = TimeSpan.Zero
        };
    });

// Add authorization services
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireImageGalleryApiFullaccessRole", policy =>
        policy.RequireRole("imagegalleryapi.fullaccess"));
});

builder.Services.AddControllers()
    .AddJsonOptions(configure => configure.JsonSerializerOptions.PropertyNamingPolicy = null);

builder.Services.AddDbContext<GalleryContext>(options =>
{
    options.UseSqlite(
        builder.Configuration["ConnectionStrings:ImageGalleryDBConnectionString"]);
});

// register the repository
builder.Services.AddScoped<IGalleryRepository, GalleryRepository>();

// register AutoMapper-related services
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

var app = builder.Build();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseStaticFiles();

app.MapControllers();

await app.RunAsync();
