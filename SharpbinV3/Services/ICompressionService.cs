namespace SharpbinV3.Services
{
    public interface ICompressionService
    {
        byte[] Compress(byte[] data);
        byte[] Decompress(byte[] compressedData);
    }
}
