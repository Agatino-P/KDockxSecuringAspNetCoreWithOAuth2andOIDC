using ImageGallery.Client.ViewModels;
using ImageGallery.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace ImageGallery.Client.Controllers;

[Authorize]
public class GalleryController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GalleryController> _logger;

    public GalleryController(IHttpClientFactory httpClientFactory,
        ILogger<GalleryController> logger)
    {
        _httpClientFactory = httpClientFactory ??
            throw new ArgumentNullException(nameof(httpClientFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    [HttpGet("/free")]
    public IActionResult Free()
    {
        
        
        return Content($"Free {User?.Identity?.Name}");
    }

    [Authorize(Roles = "paying_user")]
    [HttpGet("/pay")]
    public IActionResult Pay()
    {
        return Content($"Pay {User?.Identity?.Name}");
    }

    [HttpGet("/claims")]
    public IActionResult Claims()
    {
        var claims = User.Claims.Select(c => $"{c.Type}: {c.Value}");
        var roles = string.Join(", ", User.Claims.Where(c => c.Type == "role").Select(c => c.Value));
        var isInRole = User.IsInRole("paying_user");
        return Content($"Claims:\n{string.Join("\n", claims)}\n\nRoles: {roles}\n\nIsInRole(\"paying_user\"): {isInRole}");
    }

    public async Task<IActionResult> Index()
    {

        await LogIdentityInformation();
        await LogAccessInformation();

        var httpClient = _httpClientFactory.CreateClient("APIClient");

        var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/api/images/");

        var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        using (var responseStream = await response.Content.ReadAsStreamAsync())
        {
            var images = await JsonSerializer.DeserializeAsync<List<Image>>(responseStream);
            return View(new GalleryIndexViewModel(images ?? new List<Image>()));
        }
    }

    public async Task<IActionResult> EditImage(Guid id)
    {

        var httpClient = _httpClientFactory.CreateClient("APIClient");

        var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/images/{id}");

        var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        using (var responseStream = await response.Content.ReadAsStreamAsync())
        {
            var deserializedImage = await JsonSerializer.DeserializeAsync<Image>(responseStream);

            if (deserializedImage == null)
            {
                throw new Exception("Deserialized image must not be null.");
            }

            var editImageViewModel = new EditImageViewModel()
            {
                Id = deserializedImage.Id,
                Title = deserializedImage.Title
            };

            return View(editImageViewModel);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditImage(EditImageViewModel editImageViewModel)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        // create an ImageForUpdate instance
        var imageForUpdate = new ImageForUpdate(editImageViewModel.Title);

        // serialize it
        var serializedImageForUpdate = JsonSerializer.Serialize(imageForUpdate);

        var httpClient = _httpClientFactory.CreateClient("APIClient");

        var request = new HttpRequestMessage(
            HttpMethod.Put,
            $"/api/images/{editImageViewModel.Id}")
        {
            Content = new StringContent(
                serializedImageForUpdate,
                System.Text.Encoding.Unicode,
                "application/json")
        };

        var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead);

        response.EnsureSuccessStatusCode();

        return RedirectToAction("Index");
    }

    public async Task<IActionResult> DeleteImage(Guid id)
    {
        var httpClient = _httpClientFactory.CreateClient("APIClient");

        var request = new HttpRequestMessage(
            HttpMethod.Delete,
            $"/api/images/{id}");

        var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead);

        response.EnsureSuccessStatusCode();

        return RedirectToAction("Index");
    }

    public IActionResult AddImage()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddImage(AddImageViewModel addImageViewModel)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        // create an ImageForCreation instance
        ImageForCreation? imageForCreation = null;

        // take the first (only) file in the Files list
        var imageFile = addImageViewModel.Files.First();

        if (imageFile.Length > 0)
        {
            using (var fileStream = imageFile.OpenReadStream())
            using (var ms = new MemoryStream())
            {
                fileStream.CopyTo(ms);
                imageForCreation = new ImageForCreation(
                    addImageViewModel.Title, ms.ToArray());
            }
        }

        // serialize it
        var serializedImageForCreation = JsonSerializer.Serialize(imageForCreation);

        var httpClient = _httpClientFactory.CreateClient("APIClient");

        var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"/api/images")
        {
            Content = new StringContent(
                serializedImageForCreation,
                System.Text.Encoding.Unicode,
                "application/json")
        };

        var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        return RedirectToAction("Index");
    }

    private async Task LogIdentityInformation()
    {
        string? identityToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
        StringBuilder sb = new();
        foreach (var claim in User.Claims)
        {
            sb.AppendLine($"Claim type:{claim.Type} - Claim value: {claim.Value}");
        }
        _logger.LogInformation("""
            At {Now}
            Identity token: {IdentityToken}
            User claims: {UserClaims}
            """,
            DateTime.Now, identityToken, sb);
    }

    private async Task LogAccessInformation()
    {
        var handler = new JwtSecurityTokenHandler();
        var token = await HttpContext.GetTokenAsync("access_token");

        if (!string.IsNullOrEmpty(token))
        {
            Console.WriteLine($"[Access Token]: {token}");
            var jwt = handler.ReadJwtToken(token);
            foreach (var claim in jwt.Claims)
            {
                Console.WriteLine($"Access Token claim: {claim.Type} = {claim.Value}");
            }
        }
    }
}
