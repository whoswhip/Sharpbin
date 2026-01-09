using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
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
    public class UserController(UserService userService, AppDbContext db, TotpVerificationProvider totp, VerificationService verificationService, IOptions<AuthSettings> authSettings) : ControllerBase
    {
        private readonly UserService _userService = userService;
        private readonly AppDbContext _db = db;
        private readonly TotpVerificationProvider _totp = totp;
        private readonly VerificationService _verificationService = verificationService;
        private readonly AuthSettings _authSettings = authSettings.Value;

        [HttpGet("{username}")]
        public async Task<IActionResult> GetByUsername(string username, [FromQuery] int page = 1)
        {
            var user = await _userService.GetByUsername(username, withPastes: true);
            return user == null ? NotFound(new { success = false, message = "User not found." }) : Ok(await BuildUserResponse(user, page));
        }

        [HttpGet("uuid/{uuid}")]
        public async Task<IActionResult> GetByUUID(Guid uuid, [FromQuery] int page = 1)
        {
            var user = await _userService.GetByUUID(uuid, withPastes: true);
            return user == null ? NotFound(new { success = false, message = "User not found."}) : Ok(await BuildUserResponse(user, page));
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetMe([FromQuery] int page = 1)
        {
            var userUUID = HttpContext.User?.FindFirst("UUID")?.Value;
            if (userUUID is null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            var user = await _userService.GetByUUID(Guid.Parse(userUUID), withPastes: true);
            return user == null ? NotFound(new { success = false, message = "User not found."}) : Ok(await BuildUserResponse(user, page));
        }

        [HttpPatch("uuid/{uuid}")]
        [Authorize]
        public async Task<IActionResult> UpdateByUUID(Guid uuid, [FromBody] UpdateUserDto updatedUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var jwtUser = HttpContext.GetJwtUser();
            if (jwtUser == null) 
                return Unauthorized(new { success = false, message = "Invalid token." });

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            if ((user.Roles.Contains(255) && !jwtUser.Roles.Contains(255)) || (!jwtUser.Roles.Any(r => r == 1 || r == 255) && user.UUID != jwtUser.UUID))
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
                    if (string.IsNullOrEmpty(updatedUser.TotpCode) || !await _totp.VerifyAsync(new VerificationContext
                    {
                        UserUUID = jwtUser.UUID,
                        Code = updatedUser.TotpCode
                    }))
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
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> DeleteByUUID(Guid uuid, [FromBody] DeleteUserDto dto)
        {
            var jwtUser = HttpContext.GetJwtUser();
            if (jwtUser == null) 
                return Unauthorized(new { success = false, message = "Invalid token." });

            var user = await _userService.GetByUUID(uuid);
            if (user == null) 
                return NotFound(new { success = false, message = "User not found." });

            if (!jwtUser.Roles.Any(r => r == 255) && user.UUID != jwtUser.UUID)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this user." });
            if (jwtUser.Roles.Contains(255) && !jwtUser.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            if (jwtUser.TotpEnabled)
            {
                if (string.IsNullOrEmpty(dto.TotpCode) || !await _totp.VerifyAsync(new VerificationContext
                {
                    UserUUID = jwtUser.UUID,
                    Code = dto.TotpCode
                }))
                {
                    return Unauthorized(new { message = "Invalid TOTP code." });
                }
            }
            else
            {
                if (string.IsNullOrEmpty(dto.Token) || !await _verificationService.VerifyAsync(new VerificationContext
                {
                    Token = dto.Token,
                    Ip = HttpContext.GetRequestIP()
                }))
                {
                    return Unauthorized(new { message = "Invalid verification token." });
                }
            }

            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
            return Ok(new { message = "User deleted successfully." });
        }

        private async Task<object> BuildUserResponse(User user, int page = 1)
        {
            var isAuthenticatedUser = HttpContext.User?.FindFirst("UUID")?.Value == user.UUID.ToString();
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
                .Select(p => new
                {
                    p.ID,
                    p.UUID,
                    p.Title,
                    p.Syntax,
                    p.Size,
                    p.TrueSize,
                    p.Views,
                    p.Visibility,
                    p.EditedAt,
                    p.ExpiresAt
                })
                .ToListAsync();

            var pagination = new
            {
                Page = page,
                PageSize = pageSize,
                TotalCount = totalCount,
                TotalPages = totalPages
            };

            if (isAuthenticatedUser)
            {
                return new
                {
                    user.UID,
                    user.Username,
                    user.UUID,
                    user.DisplayName,
                    user.Email,
                    user.LastLogin,
                    user.Roles,
                    user.Visibility,
                    Pastes = pastes,
                    Pagination = pagination
                };
            }

            return new
            {
                user.UID,
                user.Username,
                user.UUID,
                user.DisplayName,
                user.Roles,
                Pastes = pastes,
                Pagination = pagination
            };
        }
    }
}
