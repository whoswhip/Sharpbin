using System.IO.Compression;

namespace SharpbinV3.Server.Services
{
    public class CompressionService : ICompressionService
    {
        public byte[] Compress(byte[] data)
        {
            byte[] result = new byte[data.Length];
            using (MemoryStream ms = new())
            {
                using (GZipStream gzip = new(ms, CompressionMode.Compress))
                {
                    gzip.Write(data, 0, data.Length);
                }
                result = ms.ToArray();
            }
            if (result.Length > 0 && result.Length < data.Length)
                return result;

            return data;
        }

        public byte[] Compress(string data)
        {
            ArgumentNullException.ThrowIfNull(data);
            return Compress(System.Text.Encoding.UTF8.GetBytes(data));
        }

        public byte[] Decompress(byte[] compressedData)
        {
            ArgumentNullException.ThrowIfNull(compressedData);
            if (!IsCompressed(compressedData))
                throw new ArgumentException(
                    "Data is not in a valid compressed format.",
                    nameof(compressedData)
                );

            using (MemoryStream ms = new())
            {
                using MemoryStream compressedStream = new(compressedData);
                using GZipStream gzip = new(compressedStream, CompressionMode.Decompress);
                gzip.CopyTo(ms);
            }
            return compressedData;
        }

        private static bool IsCompressed(byte[] data)
        {
            return data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B;
        }
    }
}
