using System.Security.Cryptography;
using System.Text;

namespace Sharpbin
{
    public class Encryption
    {
        public static string EncryptString(string input, string password)
        {
            byte[] encryptedBytes;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Key = Encoding.UTF8.GetBytes(password.PadRight(32, ' '));
                aes.IV = new byte[16];

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                        cs.Write(inputBytes, 0, inputBytes.Length);
                    }

                    encryptedBytes = ms.ToArray();
                }
            }

            return Convert.ToBase64String(encryptedBytes);
        }
        public static string EncryptByteArray(byte[] bytes, string password)
        {
            byte[] encryptedBytes;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Key = Encoding.UTF8.GetBytes(password.PadRight(32, ' '));
                aes.IV = new byte[16];

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(bytes, 0, bytes.Length);
                    }

                    encryptedBytes = ms.ToArray();
                }
            }

            return Convert.ToBase64String(encryptedBytes);
        }

        public static string DecryptString(string input, string password)
        {
            byte[] encryptedBytes = Convert.FromBase64String(input);
            string decryptedText;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Key = Encoding.UTF8.GetBytes(password.PadRight(32, ' ')); 
                aes.IV = new byte[16];

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream(encryptedBytes))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cs))
                        {
                            decryptedText = sr.ReadToEnd();
                        }
                    }
                }
            }

            return decryptedText;
        }
        public static byte[] DecryptByteArray(byte[] input, string password)
        {
            byte[] decryptedBytes;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Key = Encoding.UTF8.GetBytes(password.PadRight(32, ' '));
                aes.IV = new byte[16];

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream(input))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        decryptedBytes = new byte[ms.Length];
                        cs.Read(decryptedBytes, 0, decryptedBytes.Length);
                    }
                }
            }

            return decryptedBytes;
        }
    }
}
