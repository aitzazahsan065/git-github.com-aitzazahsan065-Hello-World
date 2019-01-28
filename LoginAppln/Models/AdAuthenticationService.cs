using System;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using Microsoft.Owin.Security;

using LoginAppln;

namespace LoginAppln.Models
{
    public class AdAuthenticationService
    {


        public class AuthenticationResult
        {
            public AuthenticationResult(string errorMessage = null, string EmpId = null)
            {
                ErrorMessage = errorMessage;
                EmployeeID = EmpId;
            }

            public String ErrorMessage { get; private set; }
            public string EmployeeID { get; private set; }
            public Boolean IsSuccess => String.IsNullOrEmpty(ErrorMessage);
        }

        private readonly IAuthenticationManager authenticationManager;

        public AdAuthenticationService(IAuthenticationManager authenticationManager)
        {
            this.authenticationManager = authenticationManager;
        }


        /// <summary>
        /// Check if username and password matches existing account in AD. 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public AuthenticationResult SignIn(String username, String password)
        {

            //#if DEBUG
            //            //authenticates against your local machine - for development time
            //           // ContextType authenticationType = ContextType.Machine;
            //#else
            //            // authenticates against your Domain AD
            //            ContextType authenticationType = ContextType.Domain;
            //#endif
            ContextType authenticationType = ContextType.Domain;
            PrincipalContext principalContext = new PrincipalContext(authenticationType);

            bool isAuthenticated = false;
            UserPrincipal userPrincipal = null;


            try
            {
                isAuthenticated = principalContext.ValidateCredentials(username, password, ContextOptions.Negotiate);
                if (isAuthenticated)
                {
                    userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);

                }
            }
            catch (Exception)
            {
                isAuthenticated = false;
                userPrincipal = null;
            }

            if (!isAuthenticated || userPrincipal == null)
            {
                return new AuthenticationResult("Username or Password is not correct", null);
            }

            if (userPrincipal.IsAccountLockedOut())
            {
                // here can be a security related discussion weather it is worth 
                // revealing this information
                return new AuthenticationResult("Your account is locked.", null);
            }

            if (userPrincipal.Enabled.HasValue && userPrincipal.Enabled.Value == false)
            {
                // here can be a security related discussion weather it is worth 
                // revealing this information
                return new AuthenticationResult("Your account is disabled", null);
            }

            var identity = CreateIdentity(userPrincipal);

            authenticationManager.SignOut(MyAuthentication.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, identity);


            return new AuthenticationResult("", userPrincipal.EmployeeId);
        }


        private ClaimsIdentity CreateIdentity(UserPrincipal userPrincipal)
        {
            var identity = new ClaimsIdentity(MyAuthentication.ApplicationCookie, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "Active Directory"));
            identity.AddClaim(new Claim(ClaimTypes.Name, userPrincipal.SamAccountName));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userPrincipal.SamAccountName));
            if (!String.IsNullOrEmpty(userPrincipal.EmailAddress))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, userPrincipal.EmailAddress));
            }

            // add your own claims if you need to add more information stored on the cookie
            var groups = userPrincipal.GetAuthorizationGroups();
            foreach (var @group in groups)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, @group.Name));
            }

            return identity;
        }
    }

}