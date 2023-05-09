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
        readonly string app;
        readonly string secret;
        HttpClient client;
        public UserController(IConfiguration config, IHttpClientFactory factory) 
        {
            federation = config["Federation"] ?? string.Empty;
            app = config["App"] ?? string.Empty;
            secret = config["Secret"] ?? string.Empty;
            client = factory?.CreateClient() ?? new HttpClient();
            client.BaseAddress = new Uri(federation);
            client.Timeout = TimeSpan.FromSeconds(5);
        }
        [Route("/signin")]
        public async Task<IActionResult> SignIn()
        {
            HttpRequestMessage request = new(HttpMethod.Get, $"auth/api/db/status");
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.CancelAfter(3000);
            try
            {
                var result = await client.SendAsync(request, cancellationTokenSource.Token);
                if (result.EnsureSuccessStatusCode() != null)
                {
                    if (result.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        return View("SignIn");
                    }
                    else return RedirectToAction("Availability");
                }
                else
                {
                    return RedirectToAction("Availability");
                }
            }
            catch (Exception ex)
            {
                return RedirectToAction("Availability");
            }
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
            var token = auth?.Properties?.GetTokenValue("refresh_token");
            return View("Account");
        }
        [Authorize]
        [Route("/signout")]
        public async Task<IActionResult> NSignOut()
        {
            await HttpContext.SignOutAsync();
            return View("SignIn");
        }
        [AcceptVerbs("Get")]
        public async Task<IActionResult> IsUserExists(string Username)
        {
            HttpRequestMessage request = new(HttpMethod.Get, $"auth/api/account/exists?username={Username}");
            var cred = new Dictionary<string, string>
                {
                    { "client_id", app },
                    { "client_secret", secret },
                };
            request.Content = new FormUrlEncodedContent(cred);
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.CancelAfter(3000);
            try
            {
                var result = await client.SendAsync(request, cancellationTokenSource.Token);
                if (result.EnsureSuccessStatusCode() != null)
                {
                    if (result.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        return Json(await result.Content.ReadAsStringAsync());
                    }
                    else return Json("Неверный ответ от федерации удостоверений");
                }
                else
                {
                    return Json("Ошибка при обработке запроса");
                }
            }
            catch (Exception ex)
            {
                return Json("Ошибка при обработке запроса");
            }
        }
        [HttpPost]
        [Route("/signin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> NSignIn([Bind("Username,Password")] CredentialsModel pair)
        {
            if (ModelState.IsValid)
            {
                if (pair != null)
                {
                    HttpRequestMessage request = new(HttpMethod.Post, $"auth/api/signin");
                    var cred = new Dictionary<string, string>
                    {
                        { "client_id", "NAUTH" },
                        { "client_secret", "758694321" },
                        { "username", pair.Username ?? "" },
                        { "password", pair.Password ?? "" }
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
                                ClaimsIdentity identity = new(id.Claims, "Cookies");
                                ClaimsPrincipal principal = new(identity);
                                AuthenticationProperties properties = new();
                                AuthenticationToken refresh_token = new() { Name = "refresh_token", Value = auth.refresh_token };
                                properties.StoreTokens(new List<AuthenticationToken>() { refresh_token });
                                properties.IsPersistent = true;
                                await HttpContext.SignInAsync(principal, properties);
                                return RedirectToAction("Account");
                            }
                            else
                            {
                                ModelState.AddModelError("FID1", "Федерация удостоверений возвращает пустой ответ");
                                return View();
                            }
                        }
                        else
                        {
                            ModelState.AddModelError("FID0", "Федерация удостоверений не отвечает");
                            return View();
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("R0", "Ошибка при отправке запроса");
                        return View();
                    }
                }
                else
                {
                    ModelState.AddModelError("С0", "Нет идентификационной информации");
                    return View();
                }
            }
            else return View();
        }
    }
}
