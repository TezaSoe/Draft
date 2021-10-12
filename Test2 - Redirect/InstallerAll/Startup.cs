using InstallerAll.Utils;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace InstallerAll
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services
            // Use OpenId authentication
            .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            // Specify this is a web app and needs auth code flow
            .AddMicrosoftIdentityWebApp(options => {
                Configuration.Bind("AzureAd", options);

                options.Prompt = "select_account";
                //options.UseTokenLifetime = true;
                options.Events.OnTokenValidated = async context => {

                    if(context.Request.Path == "/Home/Redirect") 
                    { 
                    }

                    context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(2);
                    string tenantId = context.SecurityToken.Claims.FirstOrDefault(x => x.Type == "tid" || x.Type == "http://schemas.microsoft.com/identity/claims/tenantid")?.Value;
                    //string tenantId2 = Configuration["AzureAd:TenantId"];
                    if (string.IsNullOrWhiteSpace(tenantId))
                        throw new UnauthorizedAccessException("Unable to get tenantId from token.");

                    var tokenAcquisition = context.HttpContext.RequestServices
                        .GetRequiredService<ITokenAcquisition>();

                    var graphClient = new GraphServiceClient(
                        new DelegateAuthenticationProvider(async (request) => {
                            var token = await tokenAcquisition
                                .GetAccessTokenForUserAsync(GraphConstants.Scopes, user: context.Principal);
                            request.Headers.Authorization =
                                new AuthenticationHeaderValue("Bearer", token);
                        })
                    );

                    // Get user information from Graph
                    var user = await graphClient.Me.Request()
                        .Select(u => new {
                            u.DisplayName,
                            u.Mail,
                            u.UserPrincipalName
                        })
                        .GetAsync();

                    context.Principal.AddUserGraphInfo(user);
                };

                options.Events.OnAuthenticationFailed = context => {
                    if (context.Exception != null && context.Exception is UnauthorizedTenantException)
                    {
                        context.Response.Redirect("/Home/UnauthorizedAccess");
                        context.HandleResponse(); // Suppress the exception
                        return Task.FromResult(0);
                    }

                    var error = WebUtility.UrlEncode(context.Exception.Message);
                    context.Response
                        .Redirect($"/Home/ErrorWithMessage?message=Authentication+error&debug={error}");
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Events.OnRemoteFailure = context => {
                    if (context.Failure is OpenIdConnectProtocolException)
                    {
                        var error = WebUtility.UrlEncode(context.Failure.Message);
                        context.Response
                            .Redirect($"/Home/ErrorWithMessage?message=Sign+in+error&debug={error}");
                        context.HandleResponse();
                    }

                    return Task.FromResult(0);
                };
            })
            // Add ability to call web API (Graph)
            // and get access tokens
            .EnableTokenAcquisitionToCallDownstreamApi(options => {
                Configuration.Bind("AzureAd", options);
            }, GraphConstants.Scopes)
            // Add a GraphServiceClient via dependency injection
            .AddMicrosoftGraph(options => {
                options.Scopes = string.Join(' ', GraphConstants.Scopes);
            })
            // Use in-memory token cache
            // See https://github.com/AzureAD/microsoft-identity-web/wiki/token-cache-serialization
            .AddInMemoryTokenCaches();

            // Require authentication
            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            })
            // Add the Microsoft Identity UI pages for signin/out
            .AddMicrosoftIdentityUI();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            //app.Use(async (context, next) =>
            //{
            //    //this will be call each request.
            //    //Add headers      
            //    //context.Response.Headers.Add();

            //    //var url = context.Request.Path.Value;

            //    ////check response status code
            //    //if (context.Response.StatusCode == 404) //do something
            //    //{

            //    //}
            //    //check user
            //    if(!context.User.Identity.IsAuthenticated)
            //    {
            //        //context.Response.Redirect(context.Request.Path.Value);
            //        string redirect = "<script>window.open('http://www.google.com');</script>";
            //        await context.Response.WriteAsync(redirect);
            //    }

            //    //redirect
            //    //context.Request.Path = "some url";
            //    await next(); // will call next logic, in case here would be your controller.
            // });

            //app.Run(async context =>
            //{
            //    await context.Response.WriteAsync("Hello from 2nd delegate.");
            //});

            //app.Use(async (context, next) =>
            //{
            //    //check user
            //    if (!context.User.Identity.IsAuthenticated)
            //    {
            //        var url = context.Request.Path.Value;
            //        //string newUri = "763b589764ec.ngrok.io";
            //        //string newUrl = "";

            //        //// Rewrite to base url
            //        //if (url.Contains("/signin-oidc"))
            //        //{
            //        //    //context.Request.Host = new HostString(newUri);
            //        //    newUrl = (new HostString(newUri)).ToString();
            //        //}

            //        //redirect
            //        //await context.Response.WriteAsync("<script>window.open('" + url + "');</script>");

            //        //// Get the old endpoint to extract the RequestDelegate
            //        //var currentEndpoint = context.GetEndpoint();
            //        //var url = context.Request.Path.Value;
            //        // rewrite and continue processing
            //        //context.Request.Path = "/Home/Redirect";

            //        //context.Response.Redirect(Configuration["AzureAd:Instance"]);
            //        context.Response.Redirect(url);
            //        return;   // short circuit
            //    }

            //    await next(); // will call next logic, in case here would be your controller.
            //});

            //app.Use(async (context, next) =>
            //{
            //    string referer = context.Request.Headers["Referer"].ToString();
            //    //redirect
            //    //context.Request.Path = "some url";
            //    await next(); // will call next logic, in case here would be your controller.
            //});

            //app.Run(async context => {
            //    await context.Response.WriteAsync("<div>Inside middleware defined using app.Run</div>");
            //});

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            //app.UseCookiePolicy();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            //app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
