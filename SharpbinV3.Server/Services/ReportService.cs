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

        public async Task<Report> CreateReport(Guid reporterUUID, ReportTargetType targetType, int? pastePID, ReportType type, string description)
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
            {
                q = q.Where(r => _db.Pastes.Where(p => p.ID == query.PasteId).Select(p => (int?)p.PID).Contains(r.PastePID));
            }

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
            return await BuildReportQuery(query)
                .OrderByDescending(r => r.CreatedAt)
                .Skip((query.Page - 1) * query.PageSize)
                .Take(query.PageSize)
                .Select(r => new ReportResponseDto
                {
                    ReportID = r.ReportID,
                    Type = r.Type,
                    Status = r.Status,
                    Description = r.Description,
                    CreatedAt = r.CreatedAt,
                    UpdatedAt = r.UpdatedAt,
                    ReporterUUID = r.ReporterUUID,
                    ReporterUsername = _db.Users.Where(u => u.UUID == r.ReporterUUID).Select(u => u.Username).FirstOrDefault(),
                    ReporterDisplayName = _db.Users.Where(u => u.UUID == r.ReporterUUID).Select(u => u.DisplayName).FirstOrDefault(),
                    TargetType = r.TargetType,
                    PasteId = r.Paste != null ? r.Paste.ID : null,
                    PasteTitle = r.Paste != null ? r.Paste.Title : null,
                    UserUUID = r.UserUUID,
                    TargetUsername = r.User != null ? r.User.Username : null,
                    TargetDisplayName = r.User != null ? r.User.DisplayName : null,
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
