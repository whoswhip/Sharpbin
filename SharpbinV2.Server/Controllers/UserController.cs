using Microsoft.AspNetCore.Mvc;
using SharpbinV2.Server.Services;

namespace SharpbinV2.Server.Controllers
{
    [ApiController]
    [Route("api/users")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        private readonly DatabaseService _databaseService;
        public UserController(ILogger<UserController> logger, DatabaseService databaseService)
        {
            _logger = logger;
            _databaseService = databaseService;
        }

        [HttpGet("uuid/{uuid}")]
        public async Task<IActionResult> GetUserByUuid(string uuid)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(uuid))
                    return BadRequest(new { success = false, message = "UUID cannot be null or empty" });

                var user = await _databaseService.UserFromUUID(uuid);
                if (user == null)
                {
                    _logger.LogWarning("User not found for UUID: {Uuid}", uuid);
                    return NotFound(new { success = false, message = "User not found" });
                }

                return Ok(new
                {
                    success = true,
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.DisplayName,
                        user.Created,
                        user.LastLogin,
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by UUID: {Uuid}", uuid);
                return StatusCode(500, new { success= false, message = "Internal server error" });
            }
        }

        [HttpGet("uid/{uid}")]
        public async Task<IActionResult> GetUserByUID(int uid)
        {
            try
            {
                if (uid <= 0)
                    return BadRequest(new { success = false, message = "UID must be a positive integer" });
                var user = await _databaseService.UserFromUID(uid);
                if (user == null)
                {
                    _logger.LogWarning("User not found for UID: {Uid}", uid);
                    return NotFound(new { success = false, message = "User not found" });
                }
                return Ok(new
                {
                    success = true,
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.DisplayName,
                        user.Created,
                        user.LastLogin,
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by UID: {Uid}", uid);
                return StatusCode(500, new { success= false, message = "Internal server error" });
            }
        }

        [HttpGet("username/{username}")]
        public async Task<IActionResult> GetUserByUsername(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    return BadRequest(new { success = false, message = "Username cannot be null or empty" });
                var user = await _databaseService.UserFromUsername(username);
                if (user == null)
                {
                    _logger.LogWarning("User not found for username: {Username}", username);
                    return NotFound(new { success = false, message = "User not found" });
                }
                return Ok(new
                {
                    success = true,
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.DisplayName,
                        user.Created,
                        user.LastLogin,
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by username: {Username}", username);
                return StatusCode(500, new { success= false, message = "Internal server error" });
            }
        }

        [HttpGet("{uuid}/pastes")]
        public async Task<IActionResult> GetUserPastes(string uuid, int limit, int page)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(uuid))
                    return BadRequest(new { success = false, message = "UUID cannot be null or empty" });
                if (limit <= 0 || page < 0)
                    return BadRequest(new { success = false, message = "Invalid pagination parameters" });
                if (page == 1) page = 0;

                var user = await _databaseService.UserFromUUID(uuid);
                if (user == null)
                {
                    _logger.LogWarning("User not found for UUID: {Uuid}", uuid);
                    return NotFound(new { success = false, message = "User not found" });
                }

                int pages = await _databaseService.EnumerateUserPastes(user) / limit;
                if (page > pages)
                    return BadRequest(new { success = false, message = "Page number exceeds available pages" });

                var pastes = await _databaseService.GetPastesFromUser(user, limit, page, _logger);
                if (pastes == null || pastes.Count == 0)
                    return Ok(new { success = false, message = "No pastes found for this user."});

                var pasteList = new List<object>();
                foreach (var paste in pastes)
                {
                    if (paste == null)
                        continue;
                    pasteList.Add(new
                    {
                        paste.ID,
                        paste.UUID,
                        paste.Title,
                        paste.Syntax,
                        paste.Visibility,
                        paste.Created,
                        paste.Size,
                        paste.TrueSize,
                        paste.AuthorUUID
                    });
                }

                return Ok(new
                {
                    success = true,
                    pastes = pasteList,
                    pages
                });

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving pastes for user UUID: {Uuid}", uuid);
                return StatusCode(500, new { success= false, message = "Internal server error" });
            }
        }
    }
}
