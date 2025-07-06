using Newtonsoft.Json.Linq;
using SharpbinV2.Server.Models;
using System.Text;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV2.Server.Services
{
    public class HelperService
    {
        public static string[] ipHeaders =
        {
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
            "X-Cluster-Client-IP",
            "X-ProxyUser-IP"
        };

        public static JObject? TryParse(string json)
        {
            try
            {
                return JObject.Parse(json);
            }
            catch
            {
                return null;
            }
        }
        public static JArray? TryParseArray(string json)
        {
            try
            {
                return JArray.Parse(json);
            }
            catch
            {
                return null;
            }
        }
        public static string GenerateToken()
        {
            string randomstring = GenerateRandomString(32);
            string randomguid = Guid.NewGuid().ToString();
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(Bcrypt.HashPassword(randomstring + randomguid, Bcrypt.GenerateSalt(10))));
        }
        public static string GenerateRandomString(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
        public static RequestDetails GetRequestDetails(HttpContext context)
        {
            var requestdetails = new RequestDetails();
            var headers = context.Request.Headers;
            if (headers.ContainsKey("User-Agent"))
                requestdetails.UserAgent = headers["User-Agent"];

            requestdetails.Ip = ipHeaders
                .FirstOrDefault(header => headers.TryGetValue(header, out var ip) && !string.IsNullOrWhiteSpace(ip))
                is string matchedHeader ? headers[matchedHeader] : context.Connection.RemoteIpAddress?.ToString();

            if (headers.ContainsKey("Authorization"))
                requestdetails.Token = headers["Authorization"];
            else if (context.Request.Cookies.ContainsKey("Authorization"))
                requestdetails.Token = context.Request.Cookies["Authorization"];

            return requestdetails;
        }
        public static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }
}
