using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace CoreCMS.MVC.Auth
{
    public class AuthController<T> : Controller where T : User, new()
    {
        /// <summary>
        /// Try to login a user using his username and password.
        /// </summary>
        /// <param name="username">User's username.</param>
        /// <param name="password">User's password.</param>
        /// <returns>True if succeeded.</returns>
        public async Task<bool> TryLoginUserAsync(string username, string password)
        {
            return await Auth<T>.TryLoginUserAsync(username, password, Response);
        }

        /// <summary>
        /// Try to login the given user.
        /// </summary>
        /// <param name="user">User to login.</param>
        /// <returns>True if succeeded.</returns>
        public async Task<bool> TryLoginUserAsync(T user)
        {
            return await Auth<T>.TryLoginUserAsync(user, Response);
        }

        /// <summary>
        /// Tryies to logout the current user.
        /// </summary>
        /// <returns>If it succeeded.</returns>
        public async Task<bool> TryLogoutUserAsync()
        {
            return await Auth<T>.TryLogoutUserAsync(Response, Request);
        }

        /// <summary>
        /// Get the current logged user.
        /// </summary>
        /// <returns>The logged user if it exists otherwise null.</returns>
        public User GetCurrentUser()
        {
            return Auth<T>.GetUserFromRequest(Request);
        }

        /// <summary>
        /// Tries to createh the given user and save it into the database.
        /// </summary>
        /// <param name="user">User to be saved.</param>
        /// <returns>True if succeeded.</returns>
        public async Task<bool> TryCreateUser(T user)
        {
            return await Auth<T>.TryCreateNewUser(user);
        }

        /// <summary>
        /// Tries to delete the given user from the database.
        /// </summary>
        /// <param name="user">User to be deleted.</param>
        /// <returns>True if succeeded.</returns>
        public async Task<bool> TryDeleteUser(T user)
        {
            return await Auth<T>.TryDeleteUser(user);
        }
    }
}
