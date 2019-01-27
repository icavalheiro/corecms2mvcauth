using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Microsoft.Extensions.Primitives;

namespace CoreCMS.MVC.Auth.Tools
{
    /// <summary>
    /// Tool class to help handle IP addresses.
    /// Adapted from StackOverflow: https://stackoverflow.com/questions/28664686/how-do-i-get-client-ip-address-in-asp-net-core
    /// Original author: crokusek, https://stackoverflow.com/users/538763/crokusek
    /// </summary>
    internal static class IpTools
    {

        /// <summary>
        /// Try to returns an string IP address that should represent a reliable user IP 
        /// </summary>
        /// <param name="httpContext">Current HTTP Context.</param>
        /// <param name="tryUseXForwardHeader">User X Forward Header? (no soo reliable but necessary if user is behind proxies)</param>
        /// <returns>The ip address.</returns>
        public static string TryGetRequestIP(HttpContext httpContext, bool tryUseXForwardHeader = true, bool useOnlyFirstXFowardIp = false)
        {
            string ip = null;

            if (tryUseXForwardHeader)
            {
                if (!useOnlyFirstXFowardIp)
                {
                    ip = GetHeaderValueAs<string>(httpContext, "X-Forwarded-For");
                }
                else
                {
                    ip = GetHeaderValueAs<string>(httpContext, "X-Forwarded-For").SplitCsv().FirstOrDefault();
                }
            }

            if (ip.IsNullOrWhitespace() && httpContext.Connection?.RemoteIpAddress != null)
                ip = httpContext.Connection.RemoteIpAddress.ToString();

            if (ip.IsNullOrWhitespace())
                ip = GetHeaderValueAs<string>(httpContext, "REMOTE_ADDR");

            if (ip.IsNullOrWhitespace())
                ip = "";

            return ip;
        }

        /// <summary>
        /// Get the given HEADER NAME header from the HTTP CONTEXT.
        /// </summary>
        /// <typeparam name="T">Type to return the header value as.</typeparam>
        /// <param name="httpContext">Current HTTP Context.</param>
        /// <param name="headerName">Name of the header.</param>
        /// <returns>The header value.</returns>
        private static T GetHeaderValueAs<T>(HttpContext httpContext, string headerName)
        {
            StringValues values;

            if (httpContext.Request?.Headers?.TryGetValue(headerName, out values) ?? false)
            {
                string rawValues = values.ToString();   // writes out as Csv when there are multiple.

                if (!rawValues.IsNullOrWhitespace())
                    return (T)Convert.ChangeType(values.ToString(), typeof(T));
            }
            return default(T);
        }

        /// <summary>
        /// Splits a simple comma separated string into a list of strings.
        /// </summary>
        /// <param name="csvList">The simple CSV line to split.</param>
        /// <param name="nullOrWhitespaceInputReturnsNull">Should return null if null or just white spaces?</param>
        /// <returns>The list of columns found.</returns>
        private static List<string> SplitCsv(this string csvList, bool nullOrWhitespaceInputReturnsNull = false)
        {
            if (string.IsNullOrWhiteSpace(csvList))
                return nullOrWhitespaceInputReturnsNull ? null : new List<string>();

            return csvList
                .TrimEnd(',')
                .Split(',')
                .AsEnumerable<string>()
                .Select(s => s.Trim())
                .ToList();
        }

        /// <summary>
        /// Wrapper extension method for "String.IsNullOrWhiteSpace.
        /// </summary>
        /// <param name="s">The string to process.</param>
        /// <returns>If it is null or whitespaces only.</returns>
        private static bool IsNullOrWhitespace(this string s)
        {
            return String.IsNullOrWhiteSpace(s);
        }
    }
}
