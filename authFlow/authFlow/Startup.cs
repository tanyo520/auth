using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace authFlow
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
            services.AddAuthenticationCore(options => { options.AddScheme<AuthHandle>("myScheme", "scheme demo"); });
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.Map("/login", builder => builder.Use(next =>
            {
                return async (context) =>
                {
                    var claimIdentity = new System.Security.Claims.ClaimsIdentity("Custom");
                    claimIdentity.AddClaim(new System.Security.Claims.Claim(ClaimTypes.Name, "jim"));
                    await context.SignInAsync("myScheme", new ClaimsPrincipal(claimIdentity));
                };
            }));

            // 退出
            app.Map("/logout", builder => builder.Use(next =>
            {
                return async (context) =>
                {
                    await context.SignOutAsync("myScheme");
                };
            }));

            // 认证
            app.Use(next =>
            {
                return async (context) =>
                {
                    var result = await context.AuthenticateAsync("myScheme");
                    if (result?.Principal != null) context.User = result.Principal;
                    await next(context);
                };
            });


            // 授权
            app.Use(async (context, next) =>
            {
                var user = context.User;
                if (user?.Identity?.IsAuthenticated ?? false)
                {
                    if (user.Identity.Name != "jim") await context.ForbidAsync("myScheme");
                    else await next();
                }
                else
                {
                    await context.ChallengeAsync("myScheme");
                }
            });
            // 访问受保护资源
            app.Map("/resource", builder => builder.Run(async (context) => await context.Response.WriteAsync("Hello, ASP.NET Core!")));
            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });
        }
    }
}
