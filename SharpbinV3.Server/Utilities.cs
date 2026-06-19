using System.Security.Cryptography;

namespace SharpbinV3.Server
{
    public class Utilities
    {
        public static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string([.. Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)])]);
        }

        public static string GenerateSecureRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return RandomNumberGenerator.GetString(chars, length);
        }

        public static string ComputeSha256(string input)
        {
            var inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
            var hashBytes = SHA256.HashData(inputBytes);
            return Convert.ToHexString(hashBytes);
        }

        public static string ComputeHmacSha256(string secret, string input)
        {
            var secretBytes = System.Text.Encoding.UTF8.GetBytes(secret);
            var inputBytes = System.Text.Encoding.UTF8.GetBytes(input);

            using var hmac = new HMACSHA256(secretBytes);
            var hashBytes = hmac.ComputeHash(inputBytes);

            return Convert.ToHexString(hashBytes);
        }

        public static long TimeSpanToMilliseconds(TimeSpan value) => (long)Math.Ceiling(value.TotalMilliseconds);

        public static string FormatDuration(TimeSpan value)
        {
            if (value.TotalHours >= 1)
            {
                var hours = (int)Math.Ceiling(value.TotalHours);
                return $"{hours} hour{(hours == 1 ? "" : "s")}";
            }

            var minutes = Math.Max(1, (int)Math.Ceiling(value.TotalMinutes));
            return $"{minutes} minute{(minutes == 1 ? "" : "s")}";
        }
    }
}
