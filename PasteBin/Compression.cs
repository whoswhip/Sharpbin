using System.IO.Compression;
using System.Text;

namespace Sharpbin
{
    public class Compression
    {
        public static byte[] CompressString(string text)
        {
            byte[] compressedBytes;
            using (var ms = new MemoryStream())
            {
                using (var cs = new GZipStream(ms, CompressionMode.Compress))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                    cs.Write(inputBytes, 0, inputBytes.Length);
                }
                compressedBytes = ms.ToArray();
            }
            return compressedBytes;
        }
        public static string DecompressString(byte[] compressedBytes)
        {
            string decompressedText;
            using (var ms = new MemoryStream(compressedBytes))
            {
                using (var cs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        decompressedText = sr.ReadToEnd();
                    }
                }
            }
            return decompressedText;
        }


    }
}
