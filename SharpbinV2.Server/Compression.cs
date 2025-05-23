using System.IO.Compression;
using System.Text;

namespace SharpbinV2.Server
{
    public class Compression
    {
        // Taken from old branch
        public static async Task<byte[]> CompressString(string text)
        {
            byte[] compressedBytes;
            using (var ms = new MemoryStream())
            {
                using (var cs = new GZipStream(ms, CompressionMode.Compress))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                    await cs.WriteAsync(inputBytes, 0, inputBytes.Length);
                }
                compressedBytes = ms.ToArray();
            }
            return compressedBytes;
        }
        public static async Task<string> DecompressByteArrayToString(byte[] compressedBytes)
        {
            string decompressedText;
            using (var ms = new MemoryStream(compressedBytes))
            {
                using (var cs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        decompressedText = await sr.ReadToEndAsync();
                    }
                }
            }
            return decompressedText;
        }
        public static async Task<byte[]> DecompressByteArray(byte[] compressedBytes)
        {
            byte[] decompressedBytes;
            using (var ms = new MemoryStream(compressedBytes))
            {
                using (var cs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var msDecompressed = new MemoryStream())
                    {
                        await cs.CopyToAsync(msDecompressed);
                        decompressedBytes = msDecompressed.ToArray();
                    }
                }
            }
            return decompressedBytes;
        }
        public static async Task<bool> ShouldCompress(string text, int sizeThreshold = 512, double ratioThreshold = 0.8)
        {
            if (string.IsNullOrEmpty(text))
                return false;

            byte[] inputBytes = Encoding.UTF8.GetBytes(text);
            if (inputBytes.Length < sizeThreshold)
                return false;

            byte[] compressedBytes = await CompressString(text).ConfigureAwait(false);
            double compressionRatio = (double)compressedBytes.Length / inputBytes.Length;

            return compressionRatio < ratioThreshold;
        }
        public static bool IsCompressed(byte[] data)
        {
            return data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B;
        }
    }
}
