namespace SharpbinV3.Server.DTOs
{
    public class PasteMetadataUpdateRequest
    {
        public string? Title { get; set; }
        public string? Syntax { get; set; }
        public int? Visibility { get; set; }
        public long? ExpiresAt { get; set; }
    }
}
