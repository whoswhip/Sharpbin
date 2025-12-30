namespace SharpbinV3.Server.Services
{
    public interface ICompressionService
    {
        byte[] Compress(byte[] data);
        byte[] Compress(string data);
        byte[] Decompress(byte[] compressedData);
    }
}
