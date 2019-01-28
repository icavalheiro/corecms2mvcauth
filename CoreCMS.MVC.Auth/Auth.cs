using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using CoreCMS;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using CoreCMS.MVC.Auth.Tools;

namespace CoreCMS.MVC.Auth
{
    public static class Auth<T> where T : User, new()
    {
        /// <summary>
        /// Name of the cookie o be sent to the client's browser.
        /// Defaults to "CoreCMSAuthToken".
        /// </summary>
        public static string AUTH_COOKIE_NAME = "CoreCMSAuthToken";

        /// <summary>
        /// TimeSpan that contains how long the cookie should be valid.
        /// Defaults to 1 week (7 days).
        /// </summary>
        public static TimeSpan COOKIE_EXPIRATION_TIME = TimeSpan.FromDays(7);
        
        /// <summary>
        /// Get the current user from the Http Request.
        /// </summary>
        /// <param name="request">The Http Request.</param>
        /// <returns>The current user if he is logged in, otherwise null.</returns>
        public static T GetUserFromRequest(HttpRequest request)
        {
            //we need the token that the user holds in his browser
            var tokenEntry = GetTokenFromRequest(request);
            if (tokenEntry != null)
            {
                //For security reasons we will check if the current request has the same IP
                //as who created the token (we shall only guarantee access to who created the token)
                //if this returns false, than we are prob. facing a cracker trying to use
                //someone else's credentials
                var requestIp = IpTools.TryGetRequestIP(request.HttpContext);

                //also checks if it is not expired yet
                if (requestIp == tokenEntry.AccessIp && tokenEntry.ExpireAt.Ticks > DateTime.Now.Ticks)
                {
                    //return the user related to that token
                    var user = Cms.UserSystem.GetById(tokenEntry.UserId);
                    if(user != null)
                    {
                        //create a new instance of the derived class
                        //since we cannot just convert things...
                        //cannot convert base class to derived class
                        var t = new T
                        {
                            Id = user.Id,
                            Salt = user.Salt,
                            Username = user.Username,
                            AccessLevel = user.AccessLevel,
                            HashedPassword = user.HashedPassword
                        };
                        
                        return t;
                    }
                }
                else
                {
                    //if it has expired
                    //delete it from database since it is no longer valid
                    Task.Run(async () =>
                    {
                        await Cms.LoginTokenSystem.TryDeleteAsync(tokenEntry);
                    });
                }
            }

            //no token sent or token was invalid
            return null;
        }

        /// <summary>
        /// Tries to createh the given user and save it into the database.
        /// </summary>
        /// <param name="user">User to be saved.</param>
        /// <returns>True if succeeded.</returns>
        public static async Task<bool> TryCreateNewUser(T user)
        {
            return await Cms.UserSystem.TrySaveAsync(user);
        }

        /// <summary>
        /// Tries to delete the given user from the database.
        /// </summary>
        /// <param name="user">User to be deleted.</param>
        /// <returns>True if succeeded.</returns>
        public static async Task<bool> TryDeleteUser(T user)
        {
            return await Cms.UserSystem.TryDeleteAsync(user);
        }

        /// <summary>
        /// Retrives a login token from the Http request.
        /// </summary>
        /// <param name="request">The Http Request to be used.</param>
        /// <returns>The login token if it exists.</returns>
        public static LoginToken GetTokenFromRequest(HttpRequest request)
        {
            //get the login cookie from the cookies we received from user's browser
            var cookie = request.Cookies[AUTH_COOKIE_NAME];

            //check if it valid
            if (!string.IsNullOrEmpty(cookie) 
                && Guid.TryParse(cookie, out Guid result) 
                && result != Guid.Empty)
            {
                //retrieve the token instance from the database
                var tokenEntry = Cms.LoginTokenSystem.GetById(result);

                return tokenEntry;
            }

            //token not valid
            return null;
        }

        /// <summary>
        /// Try to login a user using its username and password.
        /// </summary>
        /// <param name="username">User's username.</param>
        /// <param name="password">User's password.</param>
        /// <param name="response">Http Response to be sent to the client.</param>
        /// <returns>If it succeeded.</returns>
        public static async Task<bool> TryLoginUserAsync(string username, string password, HttpResponse response)
        {
            //lets retrieve the user from database
            var user = Cms.UserSystem.GetByUsername(username);
            if (user != null && user.TestPassword(password))
            {
                //valid username and valid password for this given user
                //lets login it then
                return await TryLoginUserAsync(user, response);
            }

            //not a valid username or password =S
            return false;
        }

        /// <summary>
        /// Tries to login the given user from the given context into the "respose".
        /// </summary>
        /// <param name="user">User to login.</param>
        /// <param name="response">Http response to be sent to client.</param>
        /// <returns>If it succeeded.</returns>
        public static async Task<bool> TryLoginUserAsync(User user, HttpResponse response)
        {
            if (user == null || user.Id == Guid.Empty)
            {
                throw new Exception("Cannot login a user that is null or has not been saved in the database yet.");
            }

            //lets create a new token for this login
            var newToken = new LoginToken
            {
                UserId = user.Id,
                AccessIp = IpTools.TryGetRequestIP(response.HttpContext),

                //set the expiration date
                ExpireAt = DateTime.Now.AddTicks(COOKIE_EXPIRATION_TIME.Ticks)
            };

            //lets save this token in the database
            //so that we can validade it later
            var tokenSaved = await Cms.LoginTokenSystem.TrySaveAsync(newToken);

            if (tokenSaved)
            {
                //Now, lets create the cookie that the user will hold to prove he is who he is
                var cookieOptions = new CookieOptions
                {
                    Expires = newToken.ExpireAt,

                    //protection against javascript injections
                    HttpOnly = true,

                    //protection against cross domain requests
                    SameSite = SameSiteMode.Strict,

                    //force ssl only, to protect against middle man attacks
                    Secure = true
                };

                //append the cookie to the response
                response.Cookies.Append(AUTH_COOKIE_NAME, newToken.Id.ToString(), cookieOptions);
                return true;
            }

            //something went wrong
            return false;
        }
        
        /// <summary>
        /// Retrives the user from "request" and tries to logout him usign the "response".
        /// </summary>
        /// <param name="response">Http response to be sent to the client.</param>
        /// <param name="request">Http request sent from the client.</param>
        /// <returns>If it succeeded.</returns>
        public static async Task<bool> TryLogoutUserAsync(HttpResponse response, HttpRequest request)
        {
            //get the token to learn who is the current user
            var token = GetTokenFromRequest(request);
            if(token != null)
            {
                //tries to delete it from database
                var succeeded = await Cms.LoginTokenSystem.TryDeleteAsync(token);
                if (succeeded)
                {
                    //let the response knows that it must delete the token from client's browser
                    response.Cookies.Delete(AUTH_COOKIE_NAME);
                    return true;
                }
            }

            //something has failed, return false
            return false;
        }
    }
}
