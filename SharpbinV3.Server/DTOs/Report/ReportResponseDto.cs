using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.DTOs.Report
{
    public class ReportResponseDto
    {
        public int? ReportID { get; set; }
        public ReportType Type { get; set; }
        public ReportStatus Status { get; set; }
        public string? Description { get; set; }
        public long CreatedAt { get; set; }
        public long? UpdatedAt { get; set; }
        public Guid ReporterUUID { get; set; }
        public string? ReporterUsername { get; set; }
        public string? ReporterDisplayName { get; set; }
        public ReportTargetType TargetType { get; set; }
        public string? PasteId { get; set; }
        public string? PasteTitle { get; set; }
        public Guid? UserUUID { get; set; }
        public string? TargetUsername { get; set; }
        public string? TargetDisplayName { get; set; }
    }

    public class ReportOptionsDto
    {
        public string[] Types { get; set; } = [];
        public string[] Statuses { get; set; } = [];
    }
}
