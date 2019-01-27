using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CoreCMS;
using CoreCMS.MVC.Auth;
using Microsoft.AspNetCore.Mvc;
using TestApplication.Models;

namespace TestApplication.Controllers
{
    public class TestController : AuthController<TestUser>
    {
        public IActionResult Index()
        {
            var currentUser = GetCurrentUser();
            if(currentUser == null)
            {
                return RedirectToAction(nameof(Login));
            }

            ViewData["User"] = currentUser.Username;

            return View();
        }
        
        [HttpGet]
        public async Task<IActionResult> CreateUser([FromQuery] string username, [FromQuery] string password, [FromQuery] string name)
        {
            if(GetCurrentUser() == null)
            {
                return RedirectToAction(nameof(Login));
            }

            if(string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return Json(new { Status="Invalid username or password"});
            }

            var newUser = new TestUser
            {
                Username = username,
                Name = (String.IsNullOrEmpty(name)) ? "Default User Name" : name
            };

            newUser.SetPassword(password);

            var saved = await TryCreateUser(newUser);
            if (saved)
            {
                return Ok();
            }

            return Json(new { Status="Could not create user." });
        }

        [HttpGet]
        [HttpPost]
        public async Task<IActionResult> Login([FromForm] string username, [FromForm] string password)
        {
            if(GetCurrentUser() != null)
            {
                //if logged in, no need to login again
                return RedirectToAction(nameof(Index));
            }
            
            if(Request.Method.ToLower() == "post")
            {
                if(string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || !await TryLoginUserAsync(username, password))
                {
                    ViewData["Error"] = "Invalid username or password.";
                    ViewData["username"] = username;
                    ViewData["password"] = password;

                    //return login form with errors
                    return View();
                }

                //logged in with success
                return RedirectToAction(nameof(Index));
            }
            else
            {
                //not post... return login form
                return View();
            }
        }

        public async Task<IActionResult> Logout()
        {
            await TryLogoutUserAsync();
            return RedirectToAction(nameof(HomeController.Index), nameof(HomeController).Replace("Controller", ""));
        }
    }
}
