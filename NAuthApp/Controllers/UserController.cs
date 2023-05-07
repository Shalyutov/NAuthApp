using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NAuthApp.Models;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace NAuthApp.Controllers
{
    public class UserController : Controller
    {
        readonly string federation;
        HttpClient client;
        public UserController(IConfiguration config, IHttpClientFactory factory) 
        {
            federation = config["Federation"] ?? string.Empty;
            client = factory?.CreateClient() ?? new HttpClient();
            client.BaseAddress = new Uri(federation);
        }
        [Route("/signin")]
        public IActionResult SignIn()
        {
            return View("SignIn");
        }
        [Route("/availability")]
        public IActionResult Availability()
        {
            return View("Unavailable");
        }
        [Authorize]
        [Route("/account")]
        public async Task<IActionResult> Account()
        {
            var auth = await HttpContext.AuthenticateAsync();
            var token = auth.Properties.GetTokenValue("refresh_token");
            return View("Account");
        }
        [Authorize]
        [Route("/signout")]
        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync();
            return View("SignIn");
        }
        [AcceptVerbs("Get")]
        public async Task<IActionResult> IsUserExists(string Username)
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"auth/api/account/exists?username={Username}");
            var cred = new Dictionary<string, string>
                {
                    { "client_id", "NAUTH" },
                    { "client_secret", "758694321" },
                };
            request.Content = new FormUrlEncodedContent(cred);
            var result = await client.SendAsync(request);
            if (result != null)
            {
                if (result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    return Json(await result.Content.ReadAsStringAsync());
                }
                else return RedirectToAction("Unavailable");
            }
            else
            {
                return RedirectToAction("Unavailable");
            }
        }
        [HttpPost]
        [Route("/signin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SignIn([Bind("Username,Password")] CredentialsModel pair)
        {
            if (ModelState.IsValid)
            {
                if (pair != null)
                {
                    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"auth/api/signin");
                    var cred = new Dictionary<string, string>
                    {
                        { "client_id", "NAUTH" },
                        { "client_secret", "758694321" },
                        { "username", pair.Username },
                        { "password", pair.Password }
                    };
                    request.Content = new FormUrlEncodedContent(cred);
                    var result = await client.SendAsync(request);
                    if (result != null)
                    {
                        if (result.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            IdPair? auth = JsonConvert.DeserializeObject<IdPair>(await result.Content.ReadAsStringAsync());
                            if (auth != null)
                            {
                                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                                var id = handler.ReadJwtToken(auth.id_token);
                                ClaimsIdentity identity = new ClaimsIdentity(id.Claims, "Cookies");
                                ClaimsPrincipal principal = new ClaimsPrincipal(identity);
                                AuthenticationProperties properties = new AuthenticationProperties();
                                AuthenticationToken refresh_token = new AuthenticationToken() { Name = "refresh_token", Value = auth.refresh_token };
                                properties.StoreTokens(new List<AuthenticationToken>() { refresh_token });
                                properties.IsPersistent = true;
                                await HttpContext.SignInAsync(principal, properties);
                                return RedirectToAction("Account");
                            }
                            else return View();
                        }
                        else return Problem();
                    }
                    else
                    {
                        return Problem();
                    }
                }
                else
                {
                    return Problem();
                }
            }
            return View();
        }
    }
}
