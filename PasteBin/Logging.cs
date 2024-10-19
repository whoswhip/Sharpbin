using Org.BouncyCastle.Asn1.Cms;

namespace Sharpbin
{
    public class Logging
    {
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
        public static async Task LogError(string message)
        {
            Console.BackgroundColor = ConsoleColor.Red;
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"[ERROR - {DateTime.Now}] {message}");
            await File.AppendAllTextAsync("logs.log", $"[ERROR - {DateTime.Now}] {message}\n");
            Console.ResetColor();
        }
        public static async Task LogInfo(string message)
        {
            Console.WriteLine($"[INFO - {DateTime.Now}] {message}");
            await File.AppendAllTextAsync("logs.log", $"[INFO - {DateTime.Now}] {message}\n");
            Console.ResetColor();
        }
        public static async Task LogWarning(string message)
        {
            Console.BackgroundColor = ConsoleColor.Yellow;
            Console.ForegroundColor = ConsoleColor.Black;
            Console.WriteLine($"[WARNING - {DateTime.Now}] {message}");
            await File.AppendAllTextAsync("logs.log", $"[WARNING - {DateTime.Now}] {message}\n");
            Console.ResetColor();
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
