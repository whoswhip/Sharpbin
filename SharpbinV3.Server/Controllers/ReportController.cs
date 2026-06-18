using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;
using SharpbinV3.Server.DTOs.Report;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;

namespace SharpbinV3.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ReportController(
        ReportService reportService,
        PasteService pasteService,
        UserService userService,
        VerificationService verificationService
    ) : Controller
    {
        private readonly ReportService _reportService = reportService;
        private readonly PasteService _pasteService = pasteService;
        private readonly UserService _userService = userService;
        private readonly VerificationService _verificationService = verificationService;

        [Route("{reportId:int}")]
        [HttpGet]
        [EnableRateLimiting("Sliding")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> GetReportById(int reportId)
        {
            var user = HttpContext.GetJwtUser()!;

            var report = await _reportService.GetReportByID(reportId);
            if (report is null)
                return NotFound(new { success = false, message = "Report not found." });

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);
            if (!hasPrivilegedRole && report.ReporterUUID != user.UUID)
                return StatusCode(403, new { success = false, message = "You do not have permission to view this report." });

            var (Username, DisplayName) = await _reportService.GetReporterInfo(report.ReporterUUID);

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
            if (!user.Roles.HasFlag(Role.Admin) && !user.Roles.HasFlag(Role.Moderator))
                return StatusCode(403, new { success = false, message = "You do not have permission to update reports." });

            var report = await _reportService.GetReportByID(reportId);
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
            var updated = await _reportService.UpdateReport(report);
            var (Username, DisplayName) = await _reportService.GetReporterInfo(updated.ReporterUUID);

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
            if (!user.Roles.HasFlag(Role.Admin) && !user.Roles.HasFlag(Role.Moderator))
                return StatusCode(403, new { success = false, message = "You do not have permission to view pastes." });

            var query = request with { Page = Math.Max(request.Page, 1), PageSize = Math.Clamp(request.PageSize, 1, 100), UserUUID = null };

            var reports = await _reportService.GetPasteReports(query);
            var totalCount = await _reportService.GetReportCount(query);
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
            if (!user.Roles.HasFlag(Role.Admin) && !user.Roles.HasFlag(Role.Moderator))
                return StatusCode(403, new { success = false, message = "You do not have permission to view users." });

            var query = request with
            {
                Page = Math.Max(request.Page, 1),
                PageSize = Math.Clamp(request.PageSize, 1, 100),
                PastePID = null,
                PasteId = null,
            };

            var reports = await _reportService.GetUserReports(query);
            var totalCount = await _reportService.GetReportCount(query);
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
            if (!user.Roles.HasFlag(Role.Admin) && !user.Roles.HasFlag(Role.Moderator))
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

            var reports = await _reportService.GetReports(query);
            var totalCount = await _reportService.GetReportCount(query);
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

        [HttpPost("pastes/{id}/report")]
        [HttpPost("/api/paste/{id}/report")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ReportPaste(string id, [FromBody] ReportDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });
            var user = HttpContext.GetJwtUser()!;

            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            if (!await _verificationService.VerifyAsync(new VerificationContext { Token = request.VerificationToken, Ip = HttpContext.GetRequestIP() }))
                return BadRequest(new { success = false, message = "Verification failed." });

            Report report = await _reportService.CreateReport(user.UUID, ReportTargetType.Paste, paste.PID, reportType, request.Description);
            if (report == null)
                return StatusCode(500, new { success = false, message = "An error occurred while reporting the paste." });

            return Ok(
                new
                {
                    success = true,
                    message = "Paste reported successfully.",
                    report = new ReportResponseDto
                    {
                        ReportID = report.ReportID,
                        Type = report.Type,
                        Status = report.Status,
                        Description = report.Description,
                        CreatedAt = report.CreatedAt,
                        UpdatedAt = report.UpdatedAt,
                        ReporterUUID = report.ReporterUUID,
                        TargetType = report.TargetType,
                        UserUUID = report.UserUUID,
                    },
                }
            );
        }

        [HttpPatch("pastes/{id}/report/{reportId}")]
        [HttpPatch("/api/paste/{id}/report/{reportId}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ModifyPasteReport(string id, int reportId, [FromBody] ReportDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var report = await _reportService.GetReportByID(reportId);
            if (report == null || report.TargetType != ReportTargetType.Paste || report.PastePID != paste.PID)
                return NotFound(new { success = false, message = "Report not found." });

            var user = HttpContext.GetJwtUser()!;

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);
            if (report.ReporterUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this report." });

            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            report.Type = reportType;
            report.Description = request.Description;

            var updatedReport = await _reportService.UpdateReport(report);
            if (updatedReport == null)
                return StatusCode(500, new { success = false, message = "An error occurred while updating the report." });

            return Ok(new { success = true, message = "Report updated successfully." });
        }

        [HttpDelete("pastes/{id}/report/{reportId}")]
        [HttpDelete("/api/paste/{id}/report/{reportId}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> DeletePasteReport(string id, int reportId)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var report = await _reportService.GetReportByID(reportId);
            if (report == null || report.TargetType != ReportTargetType.Paste || report.PastePID != paste.PID)
                return NotFound(new { success = false, message = "Report not found." });

            var user = HttpContext.GetJwtUser()!;

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);
            if (report.ReporterUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this report." });

            bool result = await _reportService.DeleteReport(report);
            if (!result)
                return StatusCode(500, new { success = false, message = "An error occurred while deleting the report." });

            return Ok(new { success = true, message = "Report deleted successfully." });
        }

        [HttpPost("users/{uuid}/report")]
        [HttpPost("/api/user/{uuid}/report")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ReportUser(Guid uuid, [FromBody] ReportDto request)
        {
            var reporter = HttpContext.GetJwtUser()!;

            var reportedUser = await _userService.GetByUUID(uuid);
            if (reportedUser == null)
                return NotFound(new { success = false, message = "User not found." });
            if (reportedUser.UUID == reporter.UUID)
                return BadRequest(new { success = false, message = "You cannot report yourself." });
            if (reportedUser.Roles.HasFlag(Role.Admin) || reportedUser.Roles.HasFlag(Role.Moderator))
                return BadRequest(new { success = false, message = "You cannot report staff members." });
            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            if (!await _verificationService.VerifyAsync(new VerificationContext { Token = request.VerificationToken, Ip = HttpContext.GetRequestIP() }))
                return Unauthorized(new { success = false, message = "Invalid verification token." });

            Report report = await _reportService.CreateReport(reporter.UUID, ReportTargetType.User, uuid, reportType, request.Description);
            if (report == null)
                return StatusCode(500, new { success = false, message = "An error occurred while creating the report." });

            return Ok(
                new
                {
                    success = true,
                    message = "User reported successfully.",
                    report = new ReportResponseDto
                    {
                        ReportID = report.ReportID,
                        Type = report.Type,
                        Status = report.Status,
                        Description = report.Description,
                        CreatedAt = report.CreatedAt,
                        UpdatedAt = report.UpdatedAt,
                        ReporterUUID = report.ReporterUUID,
                        TargetType = report.TargetType,
                        UserUUID = report.UserUUID,
                    },
                }
            );
        }

        [HttpPatch("users/{uuid}/report/{reportId}")]
        [HttpPatch("/api/user/{uuid}/report/{reportId}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> UpdateUserReport(Guid uuid, int reportId, [FromBody] ReportDto request)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            var report = await _reportService.GetReportByID(reportId);
            if (report == null || report.UserUUID != user.UUID || report.ReporterUUID != jwtUser.UUID)
                return NotFound(new { success = false, message = "Report not found." });

            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            report.Type = reportType;
            report.Description = request.Description ?? report.Description;

            var updatedReport = await _reportService.UpdateReport(report);
            if (updatedReport == null)
                return StatusCode(500, new { success = false, message = "An error occurred while updating the report." });

            return Ok(new { success = true, message = "Report updated successfully." });
        }

        [HttpDelete("users/{uuid}/report/{reportId}")]
        [HttpDelete("/api/user/{uuid}/report/{reportId}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> DeleteUserReport(Guid uuid, int reportId)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            var report = await _reportService.GetReportByID(reportId);
            if (report == null || report.UserUUID != user.UUID || report.ReporterUUID != jwtUser.UUID)
                return NotFound(new { success = false, message = "Report not found." });

            var result = await _reportService.DeleteReport(report);
            if (!result)
                return StatusCode(500, new { success = false, message = "An error occurred while deleting the report." });

            return Ok(new { success = true, message = "Report deleted successfully." });
        }

        [HttpGet("users/{uuid}/reports")]
        [HttpGet("/api/user/{uuid}/reports")]
        [Authorize(Policy = "JwtOnly")]
        public async Task<IActionResult> GetUserReports(Guid uuid, [FromQuery] ReportQuery request)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            if (!jwtUser.Roles.HasFlag(Role.Admin))
                return StatusCode(403, new { success = false, message = "You do not have permission to view this user's reports." });

            var query = request with { UserUUID = user.UUID, Page = Math.Max(request.Page, 1), PageSize = Math.Clamp(request.PageSize, 1, 100) };
            var reports = await _reportService.GetUserReports(query);
            var totalCount = await _reportService.GetReportCount(query);
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

        [HttpGet("users/{uuid}/reports/submitted")]
        [HttpGet("/api/user/{uuid}/reports/submitted")]
        [Authorize(Policy = "JwtOnly")]
        public async Task<IActionResult> GetUserSubmittedReports(Guid uuid, [FromQuery] ReportQuery request)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            var isOwner = user.UUID == jwtUser.UUID;
            var hasPrivilegedRole = jwtUser.Roles.HasFlag(Role.Admin) || jwtUser.Roles.HasFlag(Role.Moderator);
            if (!isOwner && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to view this user's submitted reports." });

            var query = request with { ReporterUUID = user.UUID, Page = Math.Max(request.Page, 1), PageSize = Math.Clamp(request.PageSize, 1, 100) };

            var reports = await _reportService.GetReports(query);
            var totalCount = await _reportService.GetReportCount(query);
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
