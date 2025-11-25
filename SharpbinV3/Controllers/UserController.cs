using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SharpbinV3.Services;

namespace SharpbinV3.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(IUserService userService) : ControllerBase
    {
        private readonly IUserService _userService = userService;

        [HttpGet("{uid}")]
        public async Task<IActionResult> GetByUid(int uid)
        {
            var user = await _userService.GetByUID(uid);
            if (user == null) return NotFound();

            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
        [HttpGet("username/{username}")]
        public async Task<IActionResult> GetByUsername(string username)
        {
            var user = await _userService.GetByUsername(username);
            if (user == null) return NotFound();
            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
        [HttpGet("uuid/{uuid}")]
        [Authorize]
        public async Task<IActionResult> GetByUUID(Guid uuid)
        {
            var user = await _userService.GetByUUID(uuid);
            if (user == null) return NotFound();
            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
    }
}
