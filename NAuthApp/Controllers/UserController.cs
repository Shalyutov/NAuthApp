using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
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
        readonly HttpClient client;
        public UserController(IConfiguration config, IHttpClientFactory factory) 
        {
            federation = config["Federation"] ?? string.Empty;
            app = config["App"] ?? string.Empty;
            secret = config["Secret"] ?? string.Empty;
            client = factory?.CreateClient() ?? new HttpClient();
            client.BaseAddress = new Uri(federation);
            client.Timeout = TimeSpan.FromSeconds(10);
        }
        [Route("/signin")]
        [HttpGet]
        public async Task<IActionResult> SignIn()
        {
            HttpRequestMessage request = new(HttpMethod.Get, "auth/db/status");
            try
            {
                var result = await client.SendAsync(request);
                if (result != null)
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
            catch (Exception)
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
            return RedirectToAction("SignIn");
        }
        [AcceptVerbs("Get")]
        public async Task<IActionResult> IsUserExists(string Username)
        {
            HttpRequestMessage request = new(HttpMethod.Get, $"auth/account/exists?username={Username}");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            try
            {
                var result = await client.SendAsync(request);
                if (result != null)
                {
                    if (result.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        var state = await result.Content.ReadAsStringAsync();
                        if (state != "true")
                        {
                            return Json("Пользователя не существует");
                        }
                        else return Json(true);
                    }
                    else return Json("Неверный ответ от федерации удостоверений");
                }
                else
                {
                    return Json("Ошибка при обработке запроса");
                }
            }
            catch (Exception)
            {
                return Json("Ошибка при обработке запроса");
            }
        }
        [HttpPost]
        [Route("/signin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> NSignIn(CredentialsModel pair)
        {
            if (ModelState.IsValid)
            {
                HttpRequestMessage request = new(HttpMethod.Post, "auth/signin");
                var cred = new Dictionary<string, string>
                {
                    { "username", pair.Username ?? "" },
                    { "password", pair.Password ?? "" }
                };
                request.Headers.Add("client_id", new List<string>() { app });
                request.Headers.Add("client_secret", new List<string>() { secret });
                request.Content = new FormUrlEncodedContent(cred);
                var result = await client.SendAsync(request);
                if (result != null)
                {
                    if (result.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        IdPair? auth = JsonConvert.DeserializeObject<IdPair>(await result.Content.ReadAsStringAsync());
                        if (auth != null)
                        {
                            JwtSecurityTokenHandler handler = new();
                            var id = handler.ReadJwtToken(auth.id_token);
                            var refresh = handler.ReadJwtToken(auth.refresh_token);
                            ClaimsIdentity identity = new(id.Claims, "Cookies");
                            ClaimsPrincipal principal = new(identity);
                            AuthenticationProperties properties = new();
                            AuthenticationToken refresh_token = new() { Name = "refresh_token", Value = auth.refresh_token };
                            properties.StoreTokens(new List<AuthenticationToken>() { refresh_token });
                            properties.ExpiresUtc = refresh.ValidTo;
                            properties.IsPersistent = true;
                            await HttpContext.SignInAsync(principal, properties);
                            return RedirectToAction("Account");
                        }
                        else ModelState.AddModelError("", "Федерация удостоверений возвращает пустой ответ");
                    }
                    else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        ModelState.AddModelError("", "Неправильный логин или пароль");
                    }
                    else if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
                    {
                        ModelState.AddModelError("", "Неверно сформирован запрос");
                    }
                    else ModelState.AddModelError("", "Федерация удостоверений не отвечает");
                }
                else ModelState.AddModelError("", "Федерация удостоверений недоступна");
            }
            else ModelState.AddModelError("", "Форма входа заполнена неверно");
            return View("SignIn", pair);
        }
    }
}
