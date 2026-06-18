using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs.Report;

namespace SharpbinV3.Server.Services
{
    public class ReportService(AppDbContext db)
    {
        private readonly AppDbContext _db = db;

        private sealed record UserInfo(string Username, string? DisplayName);

        public async Task<Report> CreateReport(Guid reporterUUID, ReportTargetType targetType, Guid userUUID, ReportType type, string description)
        {
            var report = new Report
            {
                ReporterUUID = reporterUUID,
                TargetType = targetType,
                UserUUID = userUUID,
                Type = type,
                Description = description,
            };
            await _db.Reports.AddAsync(report);
            await _db.SaveChangesAsync();
            return report;
        }

        public async Task<Report> CreateReport(Guid reporterUUID, ReportTargetType targetType, long? pastePID, ReportType type, string description)
        {
            var report = new Report
            {
                ReporterUUID = reporterUUID,
                TargetType = targetType,
                PastePID = pastePID,
                Type = type,
                Description = description,
            };
            await _db.Reports.AddAsync(report);
            await _db.SaveChangesAsync();
            return report;
        }

        private IQueryable<Report> BuildReportQuery(ReportQuery query)
        {
            IQueryable<Report> q = _db.Reports;

            if (query.ReporterUUID != null)
                q = q.Where(r => r.ReporterUUID == query.ReporterUUID);

            if (query.UserUUID != null)
                q = q.Where(r => r.UserUUID == query.UserUUID);

            if (query.PastePID != null)
                q = q.Where(r => r.PastePID == query.PastePID);

            if (query.PasteId != null)
                q = q.Where(r => r.Paste != null && r.Paste.ID == query.PasteId);

            if (query.TargetType != null)
                q = q.Where(r => r.TargetType == query.TargetType);

            if (query.Type != null)
                q = q.Where(r => r.Type == query.Type);

            if (query.Status != null)
                q = q.Where(r => r.Status == query.Status);

            return q;
        }

        public async Task<List<ReportResponseDto>> GetPasteReports(ReportQuery query)
        {
            query = query with { TargetType = ReportTargetType.Paste, UserUUID = null };

            return await GetReports(query);
        }

        public async Task<List<ReportResponseDto>> GetUserReports(ReportQuery query)
        {
            query = query with { TargetType = ReportTargetType.User, PastePID = null };

            return await GetReports(query);
        }

        public async Task<List<ReportResponseDto>> GetReports(ReportQuery query)
        {
            var pagedReports = BuildReportQuery(query)
                .OrderByDescending(r => r.CreatedAt)
                .Skip((query.Page - 1) * query.PageSize)
                .Take(query.PageSize);

            return await pagedReports
                .GroupJoin(_db.Users, r => r.ReporterUUID, reporter => reporter.UUID, (report, reporters) => new { report, reporters })
                .SelectMany(r => r.reporters.DefaultIfEmpty(), (r, reporter) => new { r.report, reporter })
                .Select(r => new ReportResponseDto
                {
                    ReportID = r.report.ReportID,
                    Type = r.report.Type,
                    Status = r.report.Status,
                    Description = r.report.Description,
                    CreatedAt = r.report.CreatedAt,
                    UpdatedAt = r.report.UpdatedAt,
                    ReporterUUID = r.report.ReporterUUID,
                    ReporterUsername = r.reporter != null ? r.reporter.Username : null,
                    ReporterDisplayName = r.reporter != null ? r.reporter.DisplayName : null,
                    TargetType = r.report.TargetType,
                    PasteId = r.report.Paste != null ? r.report.Paste.ID : null,
                    PasteTitle = r.report.Paste != null ? r.report.Paste.Title : null,
                    UserUUID = r.report.UserUUID,
                    TargetUsername = r.report.User != null ? r.report.User.Username : null,
                    TargetDisplayName = r.report.User != null ? r.report.User.DisplayName : null,
                })
                .ToListAsync();
        }

        public async Task<(string? Username, string? DisplayName)> GetReporterInfo(Guid reporterUUID)
        {
            var info = await _db
                .Users.AsNoTracking()
                .Where(u => u.UUID == reporterUUID)
                .Select(u => new UserInfo(u.Username, u.DisplayName))
                .FirstOrDefaultAsync();

            return info is null ? (null, null) : (info.Username, info.DisplayName);
        }

        public async Task<int> GetReportCount(ReportTargetType targetType)
        {
            return await _db.Reports.Where(r => r.TargetType == targetType).CountAsync();
        }

        public async Task<int> GetReportCountByReporter(Guid reporterUUID)
        {
            return await _db.Reports.Where(r => r.ReporterUUID == reporterUUID).CountAsync();
        }

        public async Task<int> GetReportCount()
        {
            return await _db.Reports.CountAsync();
        }

        public async Task<int> GetReportCount(ReportQuery query)
        {
            return await BuildReportQuery(query).CountAsync();
        }

        public async Task<Report?> GetReportByID(int reportID)
        {
            return await _db.Reports.Include(r => r.User).Include(r => r.Paste).FirstOrDefaultAsync(r => r.ReportID == reportID);
        }

        public async Task<Report> UpdateReport(Report report)
        {
            _db.Reports.Update(report);
            await _db.SaveChangesAsync();
            return report;
        }

        public async Task<bool> DeleteReport(Report report)
        {
            _db.Reports.Remove(report);
            var result = await _db.SaveChangesAsync();
            return result > 0;
        }
    }
}
