using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.Services;
using System.Security.Claims;

namespace SharpbinV3.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(UserService userService, AppDbContext db) : ControllerBase
    {
        private readonly UserService _userService = userService;
        private readonly AppDbContext _db = db;

        [HttpGet("{username}")]
        public async Task<IActionResult> GetByUsername(string username, [FromQuery] int page = 1)
        {
            var user = await _userService.GetByUsername(username, withPastes: true);
            return user == null ? NotFound() : Ok(await BuildUserResponse(user, page));
        }

        [HttpGet("uuid/{uuid}")]
        public async Task<IActionResult> GetByUUID(Guid uuid, [FromQuery] int page = 1)
        {
            var user = await _userService.GetByUUID(uuid, withPastes: true);
            return user == null ? NotFound() : Ok(await BuildUserResponse(user, page));
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetMe([FromQuery] int page = 1)
        {
            var userUUID = HttpContext.User?.FindFirst("UUID")?.Value;
            if (userUUID is null)
                return Unauthorized(new { message = "Invalid token." });

            var user = await _userService.GetByUUID(Guid.Parse(userUUID), withPastes: true);
            return user == null ? NotFound() : Ok(await BuildUserResponse(user, page));
        }

        [HttpPatch("uuid/{uuid}")]
        [Authorize]
        public async Task<IActionResult> UpdateByUUID(Guid uuid, [FromBody] UpdateUserRequest updatedUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var jwtUser = HttpContext.User;
            var uuidClaim = jwtUser?.FindFirst("UUID")?.Value;
            if (uuidClaim == null || jwtUser == null) return Forbid();
            var userRoles = jwtUser.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => int.Parse(c.Value));

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound();
            if (!userRoles.Any(r => r == 1 || r == 255) && user.UUID != Guid.Parse(uuidClaim))
                return Forbid();

            user.DisplayName = updatedUser.DisplayName ?? user.DisplayName;
            if (userRoles.Any(r => r == 255) || user.UUID == Guid.Parse(uuidClaim)) // only admins or self
            {
                user.Email = updatedUser.Email ?? user.Email;
                user.Visibility = updatedUser.Visibility ?? user.Visibility;
            }
            await _db.SaveChangesAsync();
            return Ok(new { message = "User updated successfully." });
        }

        [HttpDelete("uuid/{uuid}")]
        [Authorize]
        public async Task<IActionResult> DeleteByUUID(Guid uuid)
        {
            var jwtUser = HttpContext.User;
            var uuidClaim = jwtUser?.FindFirst("UUID")?.Value;
            if (uuidClaim == null || jwtUser == null) return Forbid();
            var userRoles = jwtUser.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => int.Parse(c.Value));

            var user = await _userService.GetByUUID(uuid);
            if (user == null)
                return NotFound();
            if (!userRoles.Any(r => r == 255) && user.UUID != Guid.Parse(uuidClaim))
                return Forbid();

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
                if (user.Visibility == 1 || user.Visibility == 2)
                    return NotFound();
                else
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
