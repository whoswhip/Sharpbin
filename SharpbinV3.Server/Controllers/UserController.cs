using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.DTOs.Paste;
using SharpbinV3.Server.DTOs.Report;
using SharpbinV3.Server.DTOs.User;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Services.Verification.Providers;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(
        UserService userService,
        AppDbContext db,
        TotpVerificationProvider totp,
        VerificationService verificationService,
        ReportService reportServer,
        IOptions<AuthSettings> authSettings
    ) : ControllerBase
    {
        private readonly UserService _userService = userService;
        private readonly AppDbContext _db = db;
        private readonly TotpVerificationProvider _totp = totp;
        private readonly VerificationService _verificationService = verificationService;
        private readonly ReportService _reportService = reportServer;
        private readonly AuthSettings _authSettings = authSettings.Value;

        [HttpGet("{username}")]
        public async Task<IActionResult> GetByUsername(string username, [FromQuery] int page = 1)
        {
            var user = await _userService.GetByUsername(username, withPastes: true);
            return user == null ? NotFound(new { success = false, message = "User not found." }) : await BuildUserResponse(user, page);
        }

        [HttpGet("uuid/{uuid}")]
        public async Task<IActionResult> GetByUUID(Guid uuid, [FromQuery] int page = 1)
        {
            var user = await _userService.GetByUUID(uuid, withPastes: true);
            return user == null ? NotFound(new { success = false, message = "User not found." }) : await BuildUserResponse(user, page);
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetMe([FromQuery] int page = 1)
        {
            var userUUID = HttpContext.User.FindFirst("uuid")!.Value;
            var user = await _userService.GetByUUID(Guid.Parse(userUUID), withPastes: true);
            return user == null ? NotFound(new { success = false, message = "User not found." }) : await BuildUserResponse(user, page);
        }

        [HttpPatch("uuid/{uuid}")]
        [Authorize(Policy = "JwtOnly")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> UpdateByUUID(Guid uuid, [FromBody] UpdateUserDto updatedUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            if (
                (user.Roles.Contains(255) && !jwtUser.Roles.Contains(255))
                || (!jwtUser.Roles.Any(r => r == 1 || r == 255) && user.UUID != jwtUser.UUID)
            )
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this user." });

            if (jwtUser.Roles.Contains(255) && !jwtUser.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            user.DisplayName = updatedUser.DisplayName ?? user.DisplayName;
            if (jwtUser.Roles.Any(r => r == 255) || user.UUID == jwtUser.UUID) // only admins or self
            {
                user.Email = updatedUser.Email ?? user.Email;
                user.Visibility = updatedUser.Visibility ?? user.Visibility;
            }
            if (jwtUser.Roles.Contains(255))
            {
                if (updatedUser.Roles.Contains(255) && jwtUser.TotpEnabled)
                {
                    if (
                        string.IsNullOrEmpty(updatedUser.TotpCode)
                        || !await _totp.VerifyAsync(new VerificationContext { UserUUID = jwtUser.UUID, Code = updatedUser.TotpCode })
                    )
                    {
                        return Unauthorized(new { message = "Invalid TOTP code." });
                    }
                }
                user.Roles = updatedUser.Roles ?? user.Roles;
            }

            await _db.SaveChangesAsync();
            return Ok(new { message = "User updated successfully." });
        }

        [HttpDelete("uuid/{uuid}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> DeleteByUUID(Guid uuid, [FromBody] DeleteUserDto dto)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            if (!jwtUser.Roles.Any(r => r == 255) && user.UUID != jwtUser.UUID)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this user." });
            if (jwtUser.Roles.Contains(255) && !jwtUser.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            if (jwtUser.TotpEnabled)
            {
                if (
                    string.IsNullOrEmpty(dto.TotpCode)
                    || !await _totp.VerifyAsync(new VerificationContext { UserUUID = jwtUser.UUID, Code = dto.TotpCode })
                )
                {
                    return Unauthorized(new { message = "Invalid TOTP code." });
                }
            }
            else
            {
                if (
                    string.IsNullOrEmpty(dto.Token)
                    || !await _verificationService.VerifyAsync(new VerificationContext { Token = dto.Token, Ip = HttpContext.GetRequestIP() })
                )
                {
                    return Unauthorized(new { message = "Invalid verification token." });
                }
            }

            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
            return Ok(new { message = "User deleted successfully." });
        }

        [HttpPost]
        [Route("{uuid}/report")]
        [EnableRateLimiting("Sensitive")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> ReportUser(Guid uuid, [FromBody] ReportDto request)
        {
            var reporter = HttpContext.GetJwtUser()!;

            var reportedUser = await _userService.GetByUUID(uuid);
            if (reportedUser == null)
                return NotFound(new { success = false, message = "User not found." });
            if (reportedUser.UUID == reporter.UUID)
                return BadRequest(new { success = false, message = "You cannot report yourself." });
            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            if (
                !await _verificationService.VerifyAsync(
                    new VerificationContext { Token = request.VerificationToken, Ip = HttpContext.GetRequestIP() }
                )
            )
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

        [HttpPatch]
        [Route("{uuid}/report/{reportId}")]
        [EnableRateLimiting("Sensitive")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
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

            await _db.SaveChangesAsync();
            return Ok(new { success = true, message = "Report updated successfully." });
        }

        [HttpDelete]
        [Route("{uuid}/report/{reportId}")]
        [EnableRateLimiting("Sensitive")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
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

        [HttpGet]
        [Authorize(Policy = "JwtOnly")]
        [Route("{uuid}/reports")]
        public async Task<IActionResult> GetUserReports(Guid uuid, [FromQuery] ReportQuery request)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            if (!jwtUser.Roles.Any(r => r == 1 || r == 255))
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

        [HttpGet]
        [Authorize(Policy = "JwtOnly")]
        [Route("{uuid}/reports/submitted")]
        public async Task<IActionResult> GetUserSubmittedReports(Guid uuid, [FromQuery] ReportQuery request)
        {
            var jwtUser = HttpContext.GetJwtUser()!;

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            var isOwner = user.UUID == jwtUser.UUID;
            var hasPrivilegedRole = jwtUser.Roles.Any(r => r == 1 || r == 255);
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

        private async Task<IActionResult> BuildUserResponse(User user, int page = 1)
        {
            var isAuthenticatedUser = HttpContext.User?.FindFirst("uuid")?.Value == user.UUID.ToString();
            var pasteQuery = _db.Pastes.AsNoTracking().Where(p => p.AuthorUUID == user.UUID);
            if (!isAuthenticatedUser)
            {
                if (user.Visibility == 2)
                    return NotFound();
                else if (user.Visibility != 1)
                    pasteQuery = pasteQuery.Where(p => p.Visibility == 0);
            }

            if (page < 1)
                page = 1;
            const int pageSize = 50;
            var totalCount = await pasteQuery.CountAsync();
            var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
            var skip = (page - 1) * pageSize;

            var pastes = await pasteQuery
                .OrderByDescending(p => p.UUID)
                .ThenByDescending(p => p.ID)
                .Skip(skip)
                .Take(pageSize)
                .Select(p => new PasteResponseDto
                {
                    ID = p.ID,
                    UUID = p.UUID,
                    CreatedAt = p.CreatedAt,
                    Title = p.Title,
                    Syntax = p.Syntax,
                    Size = p.Size,
                    TrueSize = p.TrueSize,
                    Views = p.Views,
                    Visibility = p.Visibility,
                    EditedAt = p.EditedAt,
                    ExpiresAt = p.ExpiresAt,
                })
                .ToListAsync();

            var pagination = new
            {
                Page = page,
                PageSize = pageSize,
                TotalCount = totalCount,
                TotalPages = totalPages,
            };

            if (isAuthenticatedUser)
            {
                var reports = await _reportService.GetReports(
                    new ReportQuery
                    {
                        ReporterUUID = user.UUID,
                        Page = page,
                        PageSize = pageSize,
                    }
                );
                var reportsCount = await _reportService.GetReportCountByReporter(user.UUID);

                return Ok(
                    new
                    {
                        User = new UserResponseDto
                        {
                            UID = user.UID,
                            Username = user.Username,
                            UUID = user.UUID,
                            CreatedAt = user.CreatedAt,
                            DisplayName = user.DisplayName,
                            Email = user.Email,
                            EmailVerified = user.EmailVerified,
                            LastLogin = user.LastLogin,
                            Roles = user.Roles,
                            Visibility = user.Visibility,
                        },
                        Pastes = pastes,
                        Reports = reports,
                        Pagination = pagination,
                        ReportsPagination = new
                        {
                            Page = page,
                            PageSize = pageSize,
                            TotalCount = reportsCount,
                            TotalPages = (int)Math.Ceiling(reportsCount / (double)pageSize),
                        },
                    }
                );
            }

            return Ok(
                new
                {
                    User = new UserSimpleDto
                    {
                        UID = user.UID,
                        Username = user.Username,
                        UUID = user.UUID,
                        CreatedAt = user.CreatedAt,
                        DisplayName = user.DisplayName,
                        Roles = user.Roles,
                        Visibility = user.Visibility,
                    },
                    Pastes = pastes,
                    Pagination = pagination,
                }
            );
        }
    }
}
