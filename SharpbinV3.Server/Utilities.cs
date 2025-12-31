namespace SharpbinV3.Server
{
    public class Utilities
    {
        public readonly static string[] ipHeaders =
        [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
            "X-Cluster-Client-IP",
            "X-ProxyUser-IP"
        ];
        public static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string([.. Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)])]);
        }

        public static string GetRequestIP(HttpContext request)
        {
            foreach (var header in ipHeaders)
            {
                if (request.Request.Headers.TryGetValue(header, out Microsoft.Extensions.Primitives.StringValues value))
                {
                    var ip = value.FirstOrDefault();
                    if (!string.IsNullOrEmpty(ip))
                        return ip.Split(',')[0].Trim();
                }
            }
            return request.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
