using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs
{
    public class ReportDto
    {
        [Required]
        [MaxLength(1000)]
        public string Description { get; set; } = string.Empty;
        [Required]
        public string ReportType { get; set; } = string.Empty; // e.g., "Spam", "Abuse", etc.
        public string ReportStatus { get; set; } = "Open";
        public string? VerificationToken { get; set; }
    }
}
