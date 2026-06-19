using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;
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
        AuthService authService,
        AppDbContext db,
        TotpVerificationProvider totp,
        VerificationService verificationService,
        ReportService reportServer,
        IOptions<AuthSettings> authSettings
    ) : ControllerBase
    {
        private readonly UserService _userService = userService;
        private readonly AuthService _authService = authService;
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

        [HttpGet("uuid/{uuid}/requirements")]
        [Authorize(Policy = "JwtOnly")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> GetUserActionRequirements(Guid uuid, [FromQuery] SecurityAction action)
        {
            var jwtUser = HttpContext.GetJwtUser()!;
            var targetUser = await _userService.GetByUUID(uuid);
            if (targetUser == null)
                return NotFound(new { success = false, message = "User not found." });

            if (
                (targetUser.Roles.HasFlag(Role.Admin) && !jwtUser.Roles.HasFlag(Role.Admin))
                || (!jwtUser.Roles.HasFlag(Role.Admin) && targetUser.UUID != jwtUser.UUID)
            )
                return StatusCode(403, new { success = false, message = "You do not have permission to perform this action." });

            if (action == SecurityAction.UpdateRoles && !jwtUser.Roles.HasFlag(Role.Admin))
                return StatusCode(403, new { success = false, message = "You do not have permission to perform this action." });

            if (jwtUser.Roles.HasFlag(Role.Admin) && !jwtUser.TotpEnabled && _authSettings.Admins_Require_2FA)
            {
                return Ok(
                    new
                    {
                        success = true,
                        action,
                        requiresTotp = false,
                        blocked = true,
                        message = "2FA is required to perform this action.",
                    }
                );
            }

            return Ok(
                new
                {
                    success = true,
                    action,
                    requiresTotp = jwtUser.TotpEnabled,
                    blocked = false,
                    message = jwtUser.TotpEnabled ? "TOTP verification is required." : "No TOTP verification required.",
                }
            );
        }

        [HttpPatch("uuid/{uuid}")]
        [Authorize(Policy = "JwtOnly")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> UpdateByUUID(Guid uuid, [FromBody] UpdateUserDto updatedUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var jwtUser = HttpContext.GetJwtUser()!;
            var actorUser = await _userService.GetByUUID(jwtUser.UUID);
            if (actorUser == null)
                return Unauthorized(new { success = false, message = "User not authenticated." });

            var targetUser = await _userService.GetByUUID(uuid);
            if (targetUser == null)
                return NotFound(new { success = false, message = "User not found." });

            var actorIsAdmin = actorUser.Roles.HasFlag(Role.Admin);
            var isSelfUpdate = targetUser.UUID == actorUser.UUID;

            if ((targetUser.Roles.HasFlag(Role.Admin) && !actorIsAdmin) || (!actorIsAdmin && !isSelfUpdate))
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this user." });

            if ((updatedUser.Roles.HasValue || updatedUser.IsBanned.HasValue) && !actorIsAdmin)
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this user." });

            if (updatedUser.Email != null)
                return BadRequest(new { success = false, message = "Use the email change endpoint to update email addresses." });

            bool isSensitiveUpdate =
                (updatedUser.Roles.HasValue && updatedUser.Roles.Value != targetUser.Roles) // updating roles
                || (updatedUser.IsBanned.HasValue && updatedUser.IsBanned.Value != targetUser.IsBanned); // updating ban status

            if (actorIsAdmin && !jwtUser.TotpEnabled && _authSettings.Admins_Require_2FA && isSensitiveUpdate)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            if (isSensitiveUpdate && jwtUser.TotpEnabled)
            {
                if (
                    string.IsNullOrEmpty(updatedUser.TotpCode)
                    || !await _totp.VerifyAsync(new VerificationContext { UserUUID = actorUser.UUID, Code = updatedUser.TotpCode })
                )
                {
                    return Unauthorized(new { message = "Invalid TOTP code." });
                }
            }

            if (
                updatedUser.Roles.HasValue
                && targetUser.Roles.HasFlag(Role.Admin)
                && !updatedUser.Roles.Value.HasFlag(Role.Admin)
                && !isSelfUpdate
                && actorUser.UID > targetUser.UID
            )
            // prevents demoting of other older admins by newer admins
            // allows self demotion in case of compromisation
            {
                return StatusCode(403, new { success = false, message = "You cannot remove the admin role from this user." });
            }

            targetUser.DisplayName = updatedUser.DisplayName ?? targetUser.DisplayName;
            if (actorIsAdmin || isSelfUpdate)
            {
                targetUser.Visibility = updatedUser.Visibility ?? targetUser.Visibility;
            }
            if (actorIsAdmin)
            {
                targetUser.Roles = updatedUser.Roles ?? targetUser.Roles;
                targetUser.IsBanned = updatedUser.IsBanned ?? targetUser.IsBanned;
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

            if (!jwtUser.Roles.HasFlag(Role.Admin) && user.UUID != jwtUser.UUID)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this user." });

            var isSelfDelete = user.UUID == jwtUser.UUID;
            if (jwtUser.Roles.HasFlag(Role.Admin) && !jwtUser.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });
            if (user.Roles.HasFlag(Role.Admin))
                return StatusCode(403, new { success = false, message = "You cannot delete an admin user." });

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
            else if (isSelfDelete && user.EmailVerified && !string.IsNullOrWhiteSpace(user.Email))
            {
                if (string.IsNullOrEmpty(dto.Token) || !await _authService.VerifyAccountDeletionToken(user, dto.Token))
                {
                    return Unauthorized(new { message = "Invalid account deletion verification token." });
                }
            }

            var deletedEmail = user.EmailVerified ? user.Email : null;
            var deletedUsername = user.Username;
            _db.Users.Remove(user);
            await _db.SaveChangesAsync();

            if (!string.IsNullOrWhiteSpace(deletedEmail))
                await _authService.SendAccountDeletedNotification(deletedEmail, deletedUsername);

            return Ok(new { message = "User deleted successfully." });
        }

        [HttpPost("uuid/{uuid}/delete-verification")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> RequestDeleteVerification(Guid uuid)
        {
            var jwtUser = HttpContext.GetJwtUser()!;
            if (jwtUser.UUID != uuid)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this user." });

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            if (user.Roles.HasFlag(Role.Admin))
                return StatusCode(403, new { success = false, message = "You cannot delete an admin user." });

            if (jwtUser.TotpEnabled)
                return BadRequest(new { success = false, message = "Use TOTP to delete this account." });

            if (!user.EmailVerified || string.IsNullOrWhiteSpace(user.Email))
                return BadRequest(new { success = false, message = "A verified email address is required for email deletion verification." });

            var result = await _authService.RequestAccountDeletionVerification(user);
            if (!result.success)
            {
                if (result.retryAfter.HasValue)
                {
                    Response.Headers.RetryAfter = Math.Ceiling(result.retryAfter.Value / 1000d).ToString();
                    return StatusCode(
                        StatusCodes.Status429TooManyRequests,
                        new
                        {
                            success = false,
                            message = result.message,
                            retryAfter = result.retryAfter,
                        }
                    );
                }

                return BadRequest(new { success = false, message = result.message });
            }

            return Ok(new { success = true, message = result.message });
        }

        private async Task<IActionResult> BuildUserResponse(User user, int page = 1)
        {
            var isRequestedUser = HttpContext.User?.FindFirst("uuid")?.Value == user.UUID.ToString();
            var requester = HttpContext.GetJwtUser();
            var requesterIsStaff = requester != null && (requester.Roles.HasFlag(Role.Admin) || requester.Roles.HasFlag(Role.Moderator));
            var pasteQuery = _db.Pastes.AsNoTracking().Where(p => p.AuthorUUID == user.UUID);
            if (!isRequestedUser)
            {
                if (user.Visibility == Visibility.Private && !requesterIsStaff)
                    return NotFound();
                else if (user.Visibility != Visibility.Unlisted)
                    pasteQuery = pasteQuery.Where(p => p.Visibility == Visibility.Public);
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
                    OriginalSize = p.OriginalSize,
                    StoredSize = p.StoredSize,
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

            if (isRequestedUser)
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
                            IsBanned = user.IsBanned,
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
                        IsBanned = user.IsBanned,
                        Visibility = user.Visibility,
                    },
                    Pastes = pastes,
                    Pagination = pagination,
                }
            );
        }
    }
}
