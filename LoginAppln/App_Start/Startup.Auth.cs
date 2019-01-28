using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using LoginAppln.Models;

namespace LoginAppln
{
    
        public static class MyAuthentication
        {
            public const String ApplicationCookie = "Forms";
        }

        public partial class Startup
        {
            public void ConfigureAuth(IAppBuilder app)
            {
                // need to add UserManager into owin, because this is used in cookie invalidation
                app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = MyAuthentication.ApplicationCookie,
                    LoginPath = new PathString("/Login/Login"),
                    //Provider = new CookieAuthenticationProvider(),
                    CookieName = "MyCookieName",
                    CookieHttpOnly = true,
                    ExpireTimeSpan = TimeSpan.FromMinutes(50), // adjust to your needs
                });
            }
        }
    }
