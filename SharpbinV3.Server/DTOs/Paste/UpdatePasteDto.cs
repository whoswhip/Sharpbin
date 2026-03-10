using SharpbinV3.Server.Data.Enums;

namespace SharpbinV3.Server.DTOs.Paste
{
    public class UpdatePasteDto
    {
        public string? Title { get; set; }
        public string? Syntax { get; set; }
        public Visibility? Visibility { get; set; }
        public long? ExpiresAt { get; set; }
    }
}
