using InstallerAll.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace InstallerAll.Controllers
{
    //[ApiController]
    //[Route("[controller]")]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dn">Directory Name</param>
        /// <param name="fn">File Name</param>
        /// <returns></returns>
        [HttpGet]
        [Authorize]
        //public async Task<IActionResult> IndexAsync()
        public IActionResult Index()
        {
            //if (HttpContext.Session.Keys.Contains(".InstallerAll.Session"))
            //{
            //    // Session is not expired
            //}
            //else
            //{
            //    //Session is expired
            //    return RedirectToAction("SignIn", "Account");
            //}


            //if (HttpContext.User.Identity.IsAuthenticated)
            //{
            //    var authProperties = new AuthenticationProperties
            //    {
            //        AllowRefresh = false,
            //        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(1),
            //        IsPersistent = true
            //    };

            //    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User, authProperties);
            //    //var claimsIdentity = User.Identity as ClaimsIdentity;

            //    //var scheme = OpenIdConnectDefaults.AuthenticationScheme;
            //    //string redirect = Url.Content("~/")!;
            //    //return Challenge(new AuthenticationProperties { RedirectUri = redirect },scheme);

            //    //await HttpContext.SignInAsync(User);

            //    // delete local authentication cookie
            //    //await HttpContext.SignOutAsync();
            //}

            var query = this.Request.QueryString;

            if (string.IsNullOrEmpty(query.Value))
            {
                return Ok();
                //return View();
            }

            var nvc = HttpUtility.ParseQueryString(query.Value);

            string dnfnPath = "";

            //NameValueCollection newNVC = new NameValueCollection();
            // Rewrite parameters
            foreach (string key in nvc.AllKeys)
            {
                if ("dn".Equals(key))
                {
                    dnfnPath += nvc[key];
                    nvc.Remove(key);
                    continue;
                }
                else if ("fn".Equals(key))
                {
                    if (!string.IsNullOrEmpty(dnfnPath))
                    {
                        dnfnPath += "/";
                    }
                    dnfnPath += nvc[key];
                    nvc.Remove(key);
                    continue;
                }
                //newNVC[key] = nvc[key];
            }

            if (!string.IsNullOrEmpty(dnfnPath) && !string.IsNullOrEmpty(query.Value))
            {
                //var authProperties = new AuthenticationProperties
                //{
                //    AllowRefresh = false,
                //    ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60),
                //    IsPersistent = true
                //};

                //await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User, authProperties);
                //await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                string url = _configuration["AzureAd:BlobUrl"] + dnfnPath + "?" + nvc;
                return Redirect(url);
            }
            else
            {
                return Ok();
                //string alertmsg = "You have signed-in with an user account from a Tenant that hasn't on-boarded this application yet.";
                //return Content("<script language='javascript' type='text/javascript'>alert('" + alertmsg + "');</script>");
            }
        }

        public IActionResult Privacy()
        {
            return View();
        }

        /// <summary>
        /// ログイン権限がない場合、エラー画面を表示
        /// </summary>
        /// <returns></returns>
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        [AllowAnonymous]
        public IActionResult UnauthorizedAccess()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
