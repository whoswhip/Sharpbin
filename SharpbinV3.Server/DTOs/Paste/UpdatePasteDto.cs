namespace SharpbinV3.Server.DTOs.Paste
{
    public class UpdatePasteDto
    {
        public string? Title { get; set; }
        public string? Syntax { get; set; }
        public int? Visibility { get; set; }
        public long? ExpiresAt { get; set; }
    }
}
