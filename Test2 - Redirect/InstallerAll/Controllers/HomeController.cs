using InstallerAll.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
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
            string referer = Request.Headers["Referer"].ToString();
            var query = this.Request.QueryString;

            if (string.IsNullOrEmpty(query.Value))
            {
                if(!string.IsNullOrEmpty(referer))
                {
                    return View();
                }
            }

            var nvc = HttpUtility.ParseQueryString(query.Value);

            string dnfnPath = "";

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
            }

            if (!string.IsNullOrEmpty(dnfnPath) && !string.IsNullOrEmpty(query.Value))
            {
                string url = _configuration["AzureAd:BlobUrl"] + dnfnPath + "?" + nvc;
                //if (referer.Contains(_configuration["AzureAd:Instance"]))
                //{
                //    return View("Redirect");
                //}
                return Redirect(url);
            }
            else
            {
                return View("Return");
            }
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Redirect()
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

        /// <summary>
        /// エラーが出た場合、エラー画面を表示
        /// </summary>
        /// <param name="message"></param>
        /// <param name="debug"></param>
        /// <returns></returns>
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        [AllowAnonymous]
        public IActionResult ErrorWithMessage(string message, string debug)
        {
            return View("Index").WithError(message, debug);
        }
    }
}
