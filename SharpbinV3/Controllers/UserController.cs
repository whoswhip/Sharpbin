using Microsoft.AspNetCore.Mvc;
using SharpbinV3.DTOs;
using SharpbinV3.Services;

namespace SharpbinV3.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(IUserService userService) : ControllerBase
    {
        private readonly IUserService _userService = userService;

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateUserDto dto)
        {
            if (await _userService.GetByUsername(dto.Username) != null)
                return Conflict("Username already exists.");

            if (!string.IsNullOrEmpty(dto.Email) && await _userService.GetByEmail(dto.Email) != null)
                return Conflict("Email already exists.");

            var user = await _userService.CreateUser(dto.Username, dto.Password, dto.Email, dto.DisplayName);

            return CreatedAtAction(nameof(GetByUid), new { uid = user.UID }, new { user.UID, user.Username, user.UUID });
        }

        [HttpGet("{uid:int}")]
        public async Task<IActionResult> GetByUid(int uid)
        {
            var user = await _userService.GetByUID(uid);
            if (user == null) return NotFound();

            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
        [HttpGet("username/{username:string}")]
        public async Task<IActionResult> GetByUsername(string username)
        {
            var user = await _userService.GetByUsername(username);
            if (user == null) return NotFound();
            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
        [HttpGet("uuid/{uuid:guid}")]
        public async Task<IActionResult> GetByUuid(Guid uuid)
        {
            var user = await _userService.GetByUUID(uuid);
            if (user == null) return NotFound();
            return Ok(new { user.UID, user.Username, user.UUID, user.DisplayName });
        }
    }
}
