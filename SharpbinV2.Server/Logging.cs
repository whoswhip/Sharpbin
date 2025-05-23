namespace SharpbinV2.Server
{
    public class Logging
    {
        public Logging()
        {
            if (!Directory.Exists("logs"))
                Directory.CreateDirectory("logs");
        }
        public void LogInfo(string message)
        {
            Console.WriteLine($"[{DateTime.Now} INFO] {message}");
            File.AppendAllText($"logs/{DateTime.Now.ToString("yyyy-MM-dd")}.log", $"[{DateTime.Now} INFO] {message}\n");
        }
        public void LogWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[{DateTime.Now} WARNING] {message}");
            File.AppendAllText($"logs/{DateTime.Now.ToString("yyyy-MM-dd")}.log", $"[{DateTime.Now} WARNING] {message}\n");
            Console.ResetColor();
        }
        public void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[{DateTime.Now} ERROR] {message}");
            File.AppendAllText($"logs/{DateTime.Now.ToString("yyyy-MM-dd")}.log", $"[{DateTime.Now} ERROR] {message}\n");
            Console.ResetColor();
        }
    }
}
