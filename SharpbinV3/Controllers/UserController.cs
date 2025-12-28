using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(IUserService userService, AppDbContext db) : ControllerBase
    {
        private readonly IUserService _userService = userService;
        private readonly AppDbContext _db = db;

        [HttpGet("{username}")]
        public async Task<IActionResult> GetByUsername(string username)
        {
            var user = await _userService.GetByUsername(username, withPastes: true);
            return user == null ? NotFound() : Ok(await BuildUserResponse(user));
        }

        [HttpGet("uuid/{uuid}")]
        public async Task<IActionResult> GetByUUID(Guid uuid)
        {
            var user = await _userService.GetByUUID(uuid, withPastes: true);
            return user == null ? NotFound() : Ok(await BuildUserResponse(user));
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetMe()
        {
            var userUUID = HttpContext.User?.FindFirst("UUID")?.Value;
            if (userUUID is null)
                return Unauthorized(new { message = "Invalid token." });
            
            var user = await _userService.GetByUUID(Guid.Parse(userUUID), withPastes: true);
            return user == null ? NotFound() : Ok(await BuildUserResponse(user));
        }

        private async Task<object> BuildUserResponse(User user)
        {
            var isAuthenticatedUser = HttpContext.User?.FindFirst("UUID")?.Value == user.UUID.ToString();
            var pasteQuery = _db.Pastes.AsNoTracking().Where(p => p.AuthorUUID == user.UUID);
            if (!isAuthenticatedUser)
                pasteQuery = pasteQuery.Where(p => p.Visibility == 0);

            var pastes = await pasteQuery.Select(p => new {
                p.UUID,
                p.Title,
                p.Syntax,
                p.Size,
                p.TrueSize,
                p.Views,
                p.Visibility,
                p.EditedAt,
                p.ExpiresAt
            }).ToListAsync();

            if (isAuthenticatedUser)
            {
                return new {
                    user.UID,
                    user.Username,
                    user.UUID,
                    user.DisplayName,
                    user.Email,
                    user.LastLogin,
                    user.Roles,
                    user.Visibility,
                    Pastes = pastes
                };
            }

            return new {
                user.UID,
                user.Username,
                user.UUID,
                user.DisplayName,
                Pastes = pastes
            };
        }
    }
}
