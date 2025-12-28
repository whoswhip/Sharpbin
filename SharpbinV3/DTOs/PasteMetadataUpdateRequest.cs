using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs
{
    public class PasteMetadataUpdateRequest
    {
        [StringLength(500)]
        public string? Title { get; set; }
        public string? Syntax { get; set; }
        public int? Visibility { get; set; }
        public long? ExpiresAt { get; set; }
    }
}
