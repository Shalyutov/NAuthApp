using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using NAuthApp.Models;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System.Text;

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
                        if (User.Identity?.IsAuthenticated ?? false)
                        {
                            return RedirectToAction("Account");
                        }
                        else return View("SignIn");
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
            var auth = await HttpContext.AuthenticateAsync();
            var refresh_token = auth?.Properties?.GetTokenValue("refresh_token") ?? "";
            string access_token = HttpContext.Session.GetString("access_token") ?? "";
            AccessPair? pair = null;
            if (string.IsNullOrEmpty(access_token))
            {
                pair = await GetAccessToken(refresh_token);
                if (pair == null)
                    return Unauthorized();//TODO: signout
                access_token = pair.access_token;
            }
            if (pair == null)
                pair = new AccessPair() { access_token = access_token, refresh_token = refresh_token };
            if (pair == null || pair.access_token == "")
                return Unauthorized();
            HttpRequestMessage request = new(HttpMethod.Get, "auth/token/revoke");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);
            var cred = new Dictionary<string, string>();
            JwtSecurityTokenHandler handler = new();
            var t = handler.ReadJwtToken(pair.refresh_token);
            cred.Add("kid", t.Header.Kid);
            request.Content = new FormUrlEncodedContent(cred);
            var result = await client.SendAsync(request);
            if (result != null)
            {
                if (result.IsSuccessStatusCode)
                {
                    await HttpContext.SignOutAsync();
                    return RedirectToAction("SignIn");
                }
            }
            var b = result.Content.ReadAsStringAsync();
            return View("Account");
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
                    return Json("Запрос не обработан");
                }
            }
            catch (Exception)
            {
                return Json("Сбой приложения");
            }
        }
        private async Task<AccessPair?> GetAccessToken(string refresh_token)
        {
            if (string.IsNullOrEmpty(refresh_token)) return null;
            HttpRequestMessage request = new(HttpMethod.Get, "auth/token");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", refresh_token);
            var result = await client.SendAsync(request);
            if (result == null) 
                return null;
            if (result.IsSuccessStatusCode)
            {
                var pair = JsonConvert.DeserializeObject<AccessPair>(await result.Content.ReadAsStringAsync());
                JwtSecurityTokenHandler handler = new();
                AuthenticationProperties properties = new();
                properties.StoreTokens(new List<AuthenticationToken>() {
                        new AuthenticationToken() { Name = "refresh_token", Value = pair?.refresh_token ?? ""}
                    });
                properties.ExpiresUtc = handler.ReadJwtToken(pair?.refresh_token ?? "").ValidTo;
                properties.IsPersistent = true;
                HttpContext.Session.SetString("access_token", pair?.access_token ?? "");
                await HttpContext.SignInAsync(HttpContext.User, properties);
                return pair;
            }
            else
            {
                return null;
            }
        }
        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateAccount(string? Phone, string? Email)
        {
            var auth = await HttpContext.AuthenticateAsync();
            string refresh_token = auth.Properties?.GetTokenValue("refresh_token") ?? "";
            string access_token = HttpContext.Session.GetString("access_token") ?? "";
            AccessPair? pair = null;
            if (string.IsNullOrEmpty(access_token))
            {
                pair = await GetAccessToken(refresh_token);
                if (pair == null)
                    return Unauthorized();//TODO: signout
                access_token = pair.access_token;
            }
            if (pair == null)
                pair = new AccessPair() { access_token = access_token, refresh_token = refresh_token };
            if (pair == null || pair.access_token == "")
                return Unauthorized();

            HttpRequestMessage request = new(HttpMethod.Put, "auth/account/update");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);

            var cred = new Dictionary<string, string>();
            if (Phone != null && Phone != "" && Phone != HttpContext.User.FindFirst(ClaimTypes.MobilePhone)?.Value)
            {
                cred.Add("phone", new StringBuilder(Phone).Remove(0,1).ToString());
            }
            if (Email != null && Email != "" && Email != HttpContext.User.FindFirst(ClaimTypes.Email)?.Value)
            {
                cred.Add("email", Email ?? "");
            }
            if (cred.Count == 0)
                return View("Account");
            request.Content = new FormUrlEncodedContent(cred);
            var result = await client.SendAsync(request);
            if (result != null)
            {
                if (result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var Claims = HttpContext.User.Claims;
                    List<Claim> updatedClaims = new List<Claim>();
                    foreach (var i in cred)
                    {
                        string issuer;
                        switch (i.Key)
                        {
                            case "phone":
                                issuer = Claims.First(claim => claim.Type == ClaimTypes.MobilePhone)?.Issuer ?? "NAuth API";
                                updatedClaims.Add(new Claim(ClaimTypes.MobilePhone, new StringBuilder(Phone).Remove(0, 1).ToString() ?? "", ClaimValueTypes.UInteger64, issuer));
                                break;
                            case "email":
                                issuer = Claims.First(claim => claim.Type == ClaimTypes.Email)?.Issuer ?? "NAuth API";
                                updatedClaims.Add(new Claim(ClaimTypes.Email, Email ?? "", ClaimValueTypes.String, issuer));
                                break;
                        }
                    }
                    foreach (var claim in Claims)
                    {
                        var item = updatedClaims.Find(match => match.Type == claim.Type);
                        if (item != null)
                        {
                            continue;
                        }
                        else
                        {
                            updatedClaims.Add(claim);
                        }
                    }
                    ClaimsIdentity identity = new(updatedClaims, "Cookies");
                    ClaimsPrincipal principal = new(identity);
                    JwtSecurityTokenHandler handler = new();
                    AuthenticationProperties properties = (await HttpContext.AuthenticateAsync())?.Properties ?? new();
                    await HttpContext.SignInAsync(principal, properties);
                }
            }
            return RedirectToAction("Account");
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
