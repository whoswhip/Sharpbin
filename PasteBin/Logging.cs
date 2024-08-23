namespace Sharpbin
{
    public class Logging
    {
        public static string Api_CreateMessage = "";
        public static async Task<Log> LogRequestAsync(HttpContext context)
        {
            Log log = new Log();
            log.Now = DateTime.Now;
            log.Method = context.Request.Method;
            log.Path = context.Request.Path;
            log.UserAgent = context.Request.Headers["User-Agent"];
            log.Referer = context.Request.Headers["Referer"];
            log.IP = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();
            return log;
        }
    }
    public class Log
    {
        public DateTime Now { get; set; }
        public string Method { get; set; }
        public string Path { get; set; }
        public string UserAgent { get; set; }
        public string Referer { get; set; }
        public string Body { get; set; }
        public string IP { get; set; }
    }
}
