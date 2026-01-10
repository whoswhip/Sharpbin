using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Services
{
    public class ReportService(AppDbContext db)
    {
        private readonly AppDbContext _db = db;
        public async Task<Report> CreateReport(Guid reporterUUID, ReportTargetType targetType, Guid userUUID, ReportType type, string description)
        {
            var report = new Report
            {
                ReporterUUID = reporterUUID,
                TargetType = targetType,
                UserUUID = userUUID,
                Type = type,
                Description = description
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

        public async Task<List<Report>> GetReports(Guid reporterUUID)
        {
            return await _db.Reports
                .Where(r => r.ReporterUUID == reporterUUID)
                .ToListAsync();
        }
        public async Task<List<Report>> GetReports(ReportTargetType targetType, int? pastePID)
        {
            return await _db.Reports
                .Where(r => r.TargetType == targetType && r.PastePID == pastePID)
                .ToListAsync();
        }

        public async Task<Report?> GetReportByID(int reportID)
        {
            return await _db.Reports
                .FirstOrDefaultAsync(r => r.ReportID == reportID);
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
