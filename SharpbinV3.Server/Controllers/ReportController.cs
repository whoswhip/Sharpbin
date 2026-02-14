using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs.Report;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ReportController(ReportService reportService) : Controller
    {
        [Route("{reportId:int}")]
        [HttpGet]
        [EnableRateLimiting("Sliding")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> GetReportById(int reportId)
        {
            var user = HttpContext.GetJwtUser()!;

            var report = await reportService.GetReportByID(reportId);
            if (report is null)
                return NotFound(new { success = false, message = "Report not found." });

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);
            if (!hasPrivilegedRole && report.ReporterUUID != user.UUID)
                return StatusCode(403, new { success = false, message = "You do not have permission to view this report." });

            var (Username, DisplayName) = await reportService.GetReporterInfo(report.ReporterUUID);

            return Ok(
                new ReportResponseDto
                {
                    ReportID = report.ReportID,
                    Type = report.Type,
                    Status = report.Status,
                    Description = report.Description,
                    CreatedAt = report.CreatedAt,
                    UpdatedAt = report.UpdatedAt,
                    ReporterUUID = report.ReporterUUID,
                    ReporterUsername = Username,
                    ReporterDisplayName = DisplayName,
                    TargetType = report.TargetType,
                    PasteId = report.Paste?.ID,
                    PasteTitle = report.Paste?.Title,
                    UserUUID = report.UserUUID,
                    TargetUsername = report.User?.Username,
                    TargetDisplayName = report.User?.DisplayName,
                }
            );
        }

        [Route("{reportId:int}")]
        [HttpPatch]
        [EnableRateLimiting("Sensitive")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> UpdateReport(int reportId, [FromBody] ReportUpdateDto request)
        {
            var user = HttpContext.GetJwtUser()!;
            if (!user.Roles.Contains(1) && !user.Roles.Contains(255))
                return StatusCode(403, new { success = false, message = "You do not have permission to update reports." });

            var report = await reportService.GetReportByID(reportId);
            if (report is null)
                return NotFound(new { success = false, message = "Report not found." });

            if (!string.IsNullOrWhiteSpace(request.Type))
            {
                Enum.TryParse<ReportType>(request.Type, true, out var reportType);
                if (!Enum.IsDefined(reportType))
                    return BadRequest(new { success = false, message = "Invalid report type." });
                report.Type = reportType;
            }

            if (!string.IsNullOrWhiteSpace(request.Status))
            {
                Enum.TryParse<ReportStatus>(request.Status, true, out var reportStatus);
                if (!Enum.IsDefined(reportStatus))
                    return BadRequest(new { success = false, message = "Invalid report status." });
                report.Status = reportStatus;
            }

            if (request.Description != null)
                report.Description = request.Description;

            report.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var updated = await reportService.UpdateReport(report);
            var (Username, DisplayName) = await reportService.GetReporterInfo(updated.ReporterUUID);

            return Ok(
                new ReportResponseDto
                {
                    ReportID = updated.ReportID,
                    Type = updated.Type,
                    Status = updated.Status,
                    Description = updated.Description,
                    CreatedAt = updated.CreatedAt,
                    UpdatedAt = updated.UpdatedAt,
                    ReporterUUID = updated.ReporterUUID,
                    ReporterUsername = Username,
                    ReporterDisplayName = DisplayName,
                    TargetType = updated.TargetType,
                    PasteId = updated.Paste?.ID,
                    PasteTitle = updated.Paste?.Title,
                    UserUUID = updated.UserUUID,
                    TargetUsername = updated.User?.Username,
                    TargetDisplayName = updated.User?.DisplayName,
                }
            );
        }

        [Route("options")]
        [HttpGet]
        public IActionResult GetReportOptions()
        {
            var validTypes = Enum.GetNames<ReportType>();
            var statuses = Enum.GetNames<ReportStatus>();
            return Ok(new ReportOptionsDto { Types = validTypes, Statuses = statuses });
        }

        [Route("pastes")]
        [HttpGet]
        [EnableRateLimiting("Sliding")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> GetReportsForPastes([FromQuery] ReportQuery request)
        {
            var user = HttpContext.GetJwtUser()!;
            if (!user.Roles.Contains(1) && !user.Roles.Contains(255))
                return StatusCode(403, new { success = false, message = "You do not have permission to view pastes." });

            var query = request with { Page = Math.Max(request.Page, 1), PageSize = Math.Clamp(request.PageSize, 1, 100), UserUUID = null };

            var reports = await reportService.GetPasteReports(query);
            var totalCount = await reportService.GetReportCount(query);
            var totalPages = (int)Math.Ceiling(totalCount / (double)query.PageSize);
            return Ok(
                new
                {
                    Reports = reports,
                    Pagination = new
                    {
                        query.Page,
                        query.PageSize,
                        TotalCount = totalCount,
                        TotalPages = totalPages,
                    },
                }
            );
        }

        [Route("users")]
        [HttpGet]
        [EnableRateLimiting("Sliding")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> GetReportsForUsers([FromQuery] ReportQuery request)
        {
            var user = HttpContext.GetJwtUser()!;
            if (!user.Roles.Contains(1) && !user.Roles.Contains(255))
                return StatusCode(403, new { success = false, message = "You do not have permission to view users." });

            var query = request with
            {
                Page = Math.Max(request.Page, 1),
                PageSize = Math.Clamp(request.PageSize, 1, 100),
                PastePID = null,
                PasteId = null,
            };

            var reports = await reportService.GetUserReports(query);
            var totalCount = await reportService.GetReportCount(query);
            var totalPages = (int)Math.Ceiling(totalCount / (double)query.PageSize);
            return Ok(
                new
                {
                    Reports = reports,
                    Pagination = new
                    {
                        query.Page,
                        query.PageSize,
                        TotalCount = totalCount,
                        TotalPages = totalPages,
                    },
                }
            );
        }

        [Route("all")]
        [HttpGet]
        [EnableRateLimiting("Sliding")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> GetAllReports(
            [FromQuery] Guid? reporterUuid,
            [FromQuery] ReportTargetType? targetType,
            [FromQuery] ReportType? type,
            [FromQuery] ReportStatus? status,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20
        )
        {
            var user = HttpContext.GetJwtUser()!;
            if (!user.Roles.Contains(1) && !user.Roles.Contains(255))
                return StatusCode(403, new { success = false, message = "You do not have permission to view reports." });

            var query = new ReportQuery
            {
                ReporterUUID = reporterUuid,
                TargetType = targetType,
                Type = type,
                Status = status,
                Page = Math.Max(page, 1),
                PageSize = Math.Clamp(pageSize, 1, 100),
            };

            var reports = await reportService.GetReports(query);
            var totalCount = await reportService.GetReportCount(query);
            var totalPages = (int)Math.Ceiling(totalCount / (double)query.PageSize);
            return Ok(
                new
                {
                    Reports = reports,
                    Pagination = new
                    {
                        query.Page,
                        query.PageSize,
                        TotalCount = totalCount,
                        TotalPages = totalPages,
                    },
                }
            );
        }
    }
}
