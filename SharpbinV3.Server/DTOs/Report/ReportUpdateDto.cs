using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs.Report
{
    public class ReportUpdateDto
    {
        public string? Status { get; set; }
        public string? Type { get; set; }

        [MaxLength(1000)]
        public string? Description { get; set; }
    }
}
