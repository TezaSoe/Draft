using InstallerAll.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
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
            //services.Configure<CookiePolicyOptions>(options =>
            //{
            //    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
            //    options.CheckConsentNeeded = context => true;
            //    options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            //    // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-5.0
            //    options.HandleSameSiteCookieCompatibility();
            //});

            services.ConfigureApplicationCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
                //options.SlidingExpiration = true;
                options.LoginPath = "~/";
                options.Events.OnRedirectToLogin = async (context) =>
                {
                        // Clean the session values
                        context.HttpContext.Session.Clear();
                        // Sign-out to AAD
                        await context.HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                        // Redirect to options.LoginPath;
                        context.Response.Redirect(context.RedirectUri);
                };
            });

            //services.AddDataProtection().SetDefaultKeyLifetime(TimeSpan.FromSeconds(20));

            //services.AddDistributedMemoryCache();

            //services.AddSession(options =>
            //{
            //    options.Cookie.Name = ".InstallerAll.Session";
            //    options.IdleTimeout = TimeSpan.FromSeconds(10);
            //    options.Cookie.IsEssential = true;
            //});

            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(1);
                options.Cookie.HttpOnly = true;
            });

            services
                // Use OpenId authentication
                .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                // Configure the OWIN pipeline to use cookie auth.
                //.AddCookie(options =>
                //{
                //    options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
                //    options.LoginPath = "~/";
                //    options.Events.OnRedirectToLogin = async (context) =>
                //    {
                //        // Clean the session values
                //        context.HttpContext.Session.Clear();
                //        // Sign-out to AAD
                //        await context.HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                //        // Redirect to options.LoginPath;
                //        context.Response.Redirect(context.RedirectUri);
                //    };
                //})
                // Specify this is a web app and needs auth code flow
                .AddMicrosoftIdentityWebApp(options => {
                    Configuration.Bind("AzureAd", options);

                    options.Prompt = "select_account";

                    options.Events.OnTokenValidated = async context => {
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

                    options.ForwardSignIn = OpenIdConnectDefaults.AuthenticationScheme;
                    options.ForwardSignOut = OpenIdConnectDefaults.AuthenticationScheme;

                    options.Events.OnAuthenticationFailed = context => {
                        if (context.Exception != null && context.Exception is UnauthorizedTenantException)
                        {
                            context.Response.Redirect("/Home/UnauthorizedTenant");
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

            //services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.FromSeconds(10));

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

            //services.AddAuthorization(options =>
            //{
            //    // By default, all incoming requests will be authorized according to the default policy
            //    options.FallbackPolicy = options.DefaultPolicy;
            //});
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
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
