using LoginAppln.Models;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace LoginAppln.Controllers
{
    public class LoginController : Controller
    {
        // GET: Login
     
        public ActionResult Login()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Login(LoginClass Login)
        {
            if (!ModelState.IsValid)
            {
                return View(Login);
            }
           
            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;
            var authService = new AdAuthenticationService(authenticationManager);

            var authenticationResult = authService.SignIn(Login.Username, Login.Password);

            if (authenticationResult.IsSuccess)
            {
                string employeeid = authenticationResult.EmployeeID;
                Session["EmployeeID"] = employeeid;
                Session["UserName"] = Login.Username;
                // Define Database authorization  
                //get roles from db to sessions
                if (employeeid!=null)
                    {
                    return RedirectToAction("PostLogin_");
                }
                

            }

            ModelState.AddModelError("", authenticationResult.ErrorMessage);
            ViewBag.ErrorMessage = authenticationResult.ErrorMessage;
            return View(Login);

        }
        public ActionResult PostLogin_()
        {
        
            if (!string.IsNullOrEmpty(Session["EmployeeID"] as string))
         {
                String EmployeeId = Session["EmployeeID"].ToString();
                string employeename = Session["UserName"].ToString();
                ViewBag.EmpId = EmployeeId;
                ViewBag.employeename = employeename;
                return View();
            }
         else
            {
                return View("Login");
            }
           
        }
        public ActionResult Logout()
        {
            Session.Abandon();
            Session.Clear();
            ViewBag.EmpId =null;
            ViewBag.employeename = null;
            FormsAuthentication.SignOut();
            return View("Login");
        }
    }
}