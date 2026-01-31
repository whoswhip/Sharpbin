using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs.Report
{
    public class ReportDto
    {
        [Required]
        [MinLength(12), MaxLength(1000)]
        public string Description { get; set; } = string.Empty;
        [Required]
        public string ReportType { get; set; } = string.Empty;
        public string ReportStatus { get; set; } = "Open";
        public string? VerificationToken { get; set; }
    }
}
