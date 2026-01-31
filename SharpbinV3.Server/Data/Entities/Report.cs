using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(ReportID), IsUnique = true)]
    [Index(nameof(ReporterUUID))]
    [Index(nameof(TargetType))]
    [Index(nameof(PastePID))]
    [Index(nameof(UserUUID))]
    public class Report
    {
        [Key]
        public int? ReportID { get; set; }

        public ReportType Type { get; set; }
        public ReportStatus Status { get; set; } = ReportStatus.Open;

        [MaxLength(1000)]
        public string? Description { get; set; }

        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        public long? UpdatedAt { get; set; }

        public Guid ReporterUUID { get; set; }

        public ReportTargetType TargetType { get; set; }
        public int? PastePID { get; set; }
        public Guid? UserUUID { get; set; }

        public Paste? Paste { get; set; }
        public User? User { get; set; }
    }


    public enum ReportStatus
    {
        Open,
        Closed
    }
    public enum ReportType
    {
        CopyrightViolation,
        IllegalContent,
        Fraud,
        Other
    }
    public enum ReportTargetType
    {
        Paste,
        User
    }
}
