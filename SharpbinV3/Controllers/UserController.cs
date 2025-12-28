using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(IUserService userService) : ControllerBase
    {
        private readonly IUserService _userService = userService;

        [HttpGet("{username}")]
        public async Task<IActionResult> GetByUsername(string username)
        {
            var user = await _userService.GetByUsername(username);
            if (user == null) return NotFound();
            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
        [HttpGet("uuid/{uuid}")]
        public async Task<IActionResult> GetByUUID(Guid uuid)
        {
            var user = await _userService.GetByUUID(uuid);
            if (user == null) return NotFound();
            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetMe()
        {
            var httpUser = HttpContext.User;
            var userUUID = httpUser?.FindFirst("UUID")?.Value;
            if (userUUID is null)
                return Unauthorized(new { message = "Invalid token." });
            var user = await _userService.GetByUUID(Guid.Parse(userUUID), true);
            if (user == null)
                return NotFound();
            var pastes = user.Pastes?.Select(p => new {
                p.UUID,
                p.Title,
                p.Syntax,
                p.Size,
                p.TrueSize,
                p.Views,
                p.Visibility,
                p.EditedAt,
                p.ExpiresAt
            });
            return Ok(new {
                user.UID,
                user.Username,
                user.UUID,
                user.DisplayName,
                user.Email,
                user.LastLogin,
                user.Roles,
                user.Visibility,
                Pastes = pastes
            });
        }
    }
}
