using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(LoginAppln.Startup))]
namespace LoginAppln
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
