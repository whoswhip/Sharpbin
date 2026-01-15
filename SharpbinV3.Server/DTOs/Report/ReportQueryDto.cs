using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.DTOs.Report
{
    public sealed record ReportQuery
    {
        public Guid? ReporterUUID { get; init; }
        public Guid? UserUUID { get; init; }
        public int? PastePID { get; init; }
        public string? PasteId { get; init; }
        public ReportTargetType? TargetType { get; init; }
        public ReportType? Type { get; init; }
        public ReportStatus? Status { get; init; }
        public int Page { get; init; } = 1;
        public int PageSize { get; init; } = 20;
    }
}
