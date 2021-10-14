using Azure.Storage.Blobs;
using InstallerAll.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
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
        public async Task<IActionResult> IndexAsync()
        //public IActionResult Index()
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

            string directoryName = "";
            string fileName = "";
            string dnfnPath = "";

            // Rewrite parameters
            foreach (string key in nvc.AllKeys)
            {
                if ("dn".Equals(key))
                {
                    //dnfnPath += nvc[key];
                    directoryName = nvc[key];
                    nvc.Remove(key);
                    continue;
                }
                else if ("fn".Equals(key))
                {
                    //if (!string.IsNullOrEmpty(dnfnPath))
                    //{
                    //    dnfnPath += "/";
                    //}
                    //dnfnPath += nvc[key];
                    fileName = nvc[key];
                    nvc.Remove(key);
                    continue;
                }
            }

            if (!string.IsNullOrEmpty(directoryName))
            {
                dnfnPath += directoryName + "/";
            }
            dnfnPath += fileName;

            string blobUrl = _configuration["AzureAd:BlobUrl"];

            if (!blobUrl.EndsWith("/"))
            {
                blobUrl += "/";
            }

            if (!string.IsNullOrEmpty(dnfnPath) && !string.IsNullOrEmpty(query.Value))
            {
                //string url = _configuration["AzureAd:BlobUrl"] + dnfnPath + "?" + nvc;
                //if (referer.Contains(_configuration["AzureAd:Instance"]))
                //{
                //    return View("Redirect");
                //}
                //return Redirect(url);

                var container = new BlobContainerClient(_configuration["AzureAd:AzureConnectionString"], directoryName);
                var blob = container.GetBlobClient(fileName);
                if (await blob.ExistsAsync())
                {
                    var a = await blob.DownloadAsync();
                    return File(a.Value.Content, a.Value.ContentType, fileName);
                }
                return BadRequest();

                //string url = blobUrl + dnfnPath + "?" + nvc;
                //if (referer.Contains(_configuration["AzureAd:Instance"]))
                //{
                //    return View("Redirect");
                //}
                //return Redirect(url);

                //var wc = new WebClient();
                ////wc.DownloadProgressChanged += (s, e) =>
                ////{
                ////    progressBar.Value = e.ProgressPercentage;
                ////};
                ////wc.DownloadFileCompleted += (s, e) =>
                ////{
                ////    progressBar.Visible = false;
                ////    // any other code to process the file
                ////};
                //var data = wc.DownloadData(url);
                //var content = new System.IO.MemoryStream(data);
                //var contentType = "APPLICATION/octet-stream";
                //return File(content, contentType, fileName);

                //using (WebClient wc = new WebClient())
                //{
                //    wc.Headers.Add("Cookie: Authentication=user"); // add a cookie header to the request
                //    try
                //    {
                //        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                //        foreach (string key in nvc.AllKeys)
                //            wc.QueryString.Add(key, nvc[key]);
                //        wc.DownloadFile(blobUrl + dnfnPath, desktopPath + System.IO.Path.DirectorySeparatorChar + fileName); // could add a file extension here
                //        // do something  with data
                //        return Ok();
                //    }
                //    catch (Exception ex)
                //    {
                //        // check exception object for the error
                //        var errMsg = ex.Message;
                //        return Ok();
                //    }
                //}
            }
            else
            {
                return View();
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
