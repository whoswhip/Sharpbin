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
            Span<byte> buffer = stackalloc byte[128];

            var result = new char[length];
            int pos = 0;

            while (pos < length)
            {
                RandomNumberGenerator.Fill(buffer);

                foreach (byte b in buffer)
                {
                    if (b >= 248)
                        continue; // 248 is the largest multiple of 62 < 256

                    result[pos++] = chars[b % chars.Length];
                    if (pos == length)
                        break;
                }
            }

            return new string(result);
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
    }
}
