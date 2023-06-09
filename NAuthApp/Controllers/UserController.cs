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
using NAuthApp.Helpers;

namespace NAuthApp.Controllers
{
    [Authorize]
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
        [AllowAnonymous]
        [Route("/signin")]
        [HttpGet]
        public async Task<IActionResult> SignIn()
        {
            HttpRequestMessage request = new(HttpMethod.Get, "health");
            try
            {
                var result = await client.SendAsync(request);
                if (result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    if (User.Identity?.IsAuthenticated ?? false)
                        return RedirectToAction("Account");
                    else 
                        return View("SignIn");
                }
                return NoService(true);
            }
            catch (Exception)
            {
                return NoService(true);
            }
        }
        [AllowAnonymous]
        [Route("/signup")]
        [HttpGet]
        public async Task<IActionResult> SignUp()
        {
            HttpRequestMessage request = new(HttpMethod.Get, "health");
            try
            {
                var result = await client.SendAsync(request);
                if (result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    return View("SignUp");
                }
                return NoService(true);
            }
            catch (Exception)
            {
                return NoService(true);
            }
        }
        [AllowAnonymous]
        [Route("/no-service")]
        public IActionResult NoService(bool problem)
        {
            if (problem)
                return View("NoService");
            else
                return RedirectToAction("SignIn");
        }
        [AllowAnonymous]
        [HttpGet("/blocked")]
        public IActionResult Blocked(bool isBlocked)
        {
            if (isBlocked) 
                return View("Blocked");
            else 
                return RedirectToAction("SignIn");
        }
        [Route("/account")]
        public async Task<IActionResult> Account()
        {
            AccessPair? pair = await GetAccessToken();
            if (pair == null || string.IsNullOrEmpty(pair.access_token) || string.IsNullOrEmpty(pair.refresh_token))
            {
                await HttpContext.SignOutAsync();
                return RedirectToAction("SignIn");
            }
            HttpRequestMessage request = new(HttpMethod.Get, "user/account");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);
            var result = await client.SendAsync(request);
            if (result == null)
                return NoService(true);
            if (result.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var response = await result.Content.ReadAsStringAsync();
                Account? account = JsonConvert.DeserializeObject<Account>(response);
                if (account == null)
                    return RedirectToAction("SignIn");
                return View("Account", account);
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                await HttpContext.SignOutAsync(new AuthenticationProperties());
                HttpContext.Session.Clear();
                return RedirectToAction("SignIn");
            }
            return View("NoService");
        }
        [Route("/account/edit")]
        public async Task<IActionResult> Edit()
        {
            AccessPair? pair = await GetAccessToken();
            if (pair == null || string.IsNullOrEmpty(pair.access_token) || string.IsNullOrEmpty(pair.refresh_token))
            {
                await HttpContext.SignOutAsync(new AuthenticationProperties());
                HttpContext.Session.Clear();
                return RedirectToAction("SignIn");
            }
            HttpRequestMessage request = new(HttpMethod.Get, "user/account");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);
            var result = await client.SendAsync(request);
            if (result == null)
                return NoService(true);
            if (result.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var response = await result.Content.ReadAsStringAsync();
                Account? account = JsonConvert.DeserializeObject<Account>(response);
                if (account == null)
                    return RedirectToAction("SignIn");
                return View("Edit", account);
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                await HttpContext.SignOutAsync(new AuthenticationProperties());
                HttpContext.Session.Clear();
                return RedirectToAction("SignIn");
            }
            return View("NoService");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string delete)
        {
            if (delete == "true")
            {
                AccessPair? pair = await GetAccessToken();
                if (pair == null || string.IsNullOrEmpty(pair.access_token) || string.IsNullOrEmpty(pair.refresh_token))
                {
                    await HttpContext.SignOutAsync(new AuthenticationProperties());
                    HttpContext.Session.Clear();
                    return RedirectToAction("SignIn");
                }
                HttpRequestMessage request = new(HttpMethod.Delete, "user/account");
                request.Headers.Add("client_id", new List<string>() { app });
                request.Headers.Add("client_secret", new List<string>() { secret });
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);
                var result = await client.SendAsync(request);
                if (result == null)
                    return NoService(true);
                if (result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    await HttpContext.SignOutAsync(new AuthenticationProperties());
                    HttpContext.Session.Clear();
                    return RedirectToAction("SignIn");
                }
                else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    await HttpContext.SignOutAsync(new AuthenticationProperties());
                    HttpContext.Session.Clear();
                    return RedirectToAction("SignIn");
                }
                return NoService(true);
            }
            return RedirectToAction("Account");
        }
        [Route("/raw")]
        public async Task<IActionResult> Raw()
        {
            AccessPair? pair = await GetAccessToken();
            if (pair == null || string.IsNullOrEmpty(pair.access_token) || string.IsNullOrEmpty(pair.refresh_token))
            {
                await HttpContext.SignOutAsync();
                return RedirectToAction("SignIn");
            }
            HttpRequestMessage request = new(HttpMethod.Get, "user/account");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);
            var result = await client.SendAsync(request);
            if (result == null)
                return NoService(true);
            if (result.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var response = await result.Content.ReadAsStringAsync();
                Account? account = JsonConvert.DeserializeObject<Account>(response);
                if (account == null)
                    return NoContent();
                return Ok(account);
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return Unauthorized();
            else 
                return Problem();
        }
        [Route("/signout")]
        public async Task<IActionResult> Signout(bool all)
        {
            var auth = await HttpContext.AuthenticateAsync();
            var token = auth.Properties?.GetTokens().First().Value;
            HttpRequestMessage request;
            if (all)
            {
                request = new(HttpMethod.Get, "auth/signout");
            }
            else
            {
                request = new(HttpMethod.Get, "auth/signout/this");
            }
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var result = await client.SendAsync(request);
            if (result != null)
            {
                if (result.IsSuccessStatusCode)
                {
                    await HttpContext.SignOutAsync(new AuthenticationProperties());
                    HttpContext.Session.Clear();
                    return RedirectToAction("SignIn");
                }
            }
            return RedirectToAction("Account");
        }
        public async Task<IActionResult> AllSignout()
        {
            return await Signout(true);
        }
        public async Task<IActionResult> ThisSignout()
        {
            return await Signout(false);
        }
        [AllowAnonymous]
        [AcceptVerbs("Get")]
        public async Task<IActionResult> IsUserExists(string Username)
        {
            HttpRequestMessage request = new(HttpMethod.Get, $"user/account/exists?username={Username}");
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
        [AllowAnonymous]
        [AcceptVerbs("Get")]
        public async Task<IActionResult> IsUserReady(string Username)
        {
            HttpRequestMessage request = new(HttpMethod.Get, $"user/account/exists?username={Username}");
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
                            return Json(true);
                        }
                        else return Json("Логин уже занят другим пользователем");
                    }
                    else return Json("Неверный ответ от федерации удостоверений");
                }
                else
                {
                    return Problem("Запрос не обработан");
                }
            }
            catch (Exception)
            {
                return Problem("Сбой приложения");
            }
        }
        private async Task<AccessPair?> GetAccessToken()
        {
            var auth = await HttpContext.AuthenticateAsync();
            string refresh_token = auth.Properties?.GetTokens().First().Value ?? string.Empty;
            string access_token = HttpContext.Session.GetString("access_token") ?? string.Empty;
            if (string.IsNullOrEmpty(refresh_token)) 
                return null;
            if (string.IsNullOrEmpty(access_token))
            {
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
                        new AuthenticationToken(){ Name = "refresh_token", Value = pair?.refresh_token ?? ""}
                    });
                    properties.SetParameter("ExpiresUtc", handler.ReadJwtToken(pair?.refresh_token ?? "").ValidTo);
                    HttpContext.Session.SetString("access_token", pair?.access_token ?? "");
                    await HttpContext.SignInAsync(HttpContext.User, properties);
                    return pair;
                }
                else
                {
                    return null;
                }
            }
            else
            {
                return new AccessPair() { refresh_token = refresh_token, access_token = access_token };
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateAccount()
        {
            AccessPair? pair = await GetAccessToken();
            if (pair == null || string.IsNullOrEmpty(pair.access_token) || string.IsNullOrEmpty(pair.refresh_token))
                return RedirectToAction("SignIn");
            if (!HttpContext.Request.HasFormContentType)
                return RedirectToAction("Account");
            var identity = HttpContext.User;
            var cred = new Dictionary<string, string>();
            var form = await HttpContext.Request.ReadFormAsync();
            foreach (var claim in form)
            {
                var type = ClaimHelper.SwitchClaims(claim.Key);
                var item = identity.FindFirst(type);
                if (item != null && item != claim.Value) 
                    cred.Add(claim.Key, claim.Value.First() ?? "");
            }
            if (cred.Count == 0)
                return RedirectToAction("Account");
            HttpRequestMessage request = new(HttpMethod.Put, "user/account");
            request.Headers.Add("client_id", new List<string>() { app });
            request.Headers.Add("client_secret", new List<string>() { secret });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.access_token);
            request.Content = new FormUrlEncodedContent(cred);
            var result = await client.SendAsync(request);
            if (result != null)
            {
                if (result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var user = HttpContext.User;
                    List<Claim> updatedClaims = new();
                    foreach (var i in cred)
                    {
                        var type = ClaimHelper.SwitchClaims(i.Key);
                        var item = identity.FindFirst(type);
                        string issuer = item?.Issuer ?? "NAuth API";
                        updatedClaims.Add(new Claim(type, i.Value, item?.ValueType ?? ClaimValueTypes.String, issuer));
                    }
                    foreach (var claim in user.Claims)
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
                    ClaimsIdentity new_identity = new(updatedClaims, "Cookies");
                    ClaimsPrincipal principal = new(new_identity);
                    JwtSecurityTokenHandler handler = new();
                    AuthenticationProperties properties = (await HttpContext.AuthenticateAsync())?.Properties ?? new();
                    await HttpContext.SignInAsync(principal, properties);
                }
            }
            return RedirectToAction("Account");
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("/signin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> NSignIn(AuthPair pair)
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
                    else if (result.StatusCode == System.Net.HttpStatusCode.Forbidden)
                    {
                        return Blocked(true);
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
        [AllowAnonymous]
        [HttpPost]
        [Route("/signup")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> NSignUp(AccountModel model)
        {
            if (ModelState.IsValid)
            {
                HttpRequestMessage request = new(HttpMethod.Post, "auth/signup");
                var cred = new Dictionary<string, string>
                {
                    { "username", model.Username ?? "" },
                    { "password", model.Password ?? "" },
                    { "surname", model.Surname ?? "" },
                    { "name", model.Name ?? "" },
                    { "lastname", model.LastName ?? "" },
                    { "email", model.Email ?? "" },
                    { "phone", model.Phone.ToString() ?? "" },
                    { "gender", model.Gender ?? "" }
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
                        ModelState.AddModelError("", "Запрет авторизации");
                    }
                    else if (result.StatusCode == System.Net.HttpStatusCode.Forbidden)
                    {
                        return Blocked(true);
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
            return View("SignUp", model);
        }
    }
}
