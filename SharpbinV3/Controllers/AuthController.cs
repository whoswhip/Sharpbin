using Microsoft.AspNetCore.Mvc;
using SharpbinV3.Services;
using SharpbinV3.DTOs;
using Bcrypt = BCrypt.Net.BCrypt;
using SharpbinV3.Data.Entities;
using Microsoft.AspNetCore.RateLimiting;

namespace SharpbinV3.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(IUserService userService, IAuthService authService) : ControllerBase
    {
        private readonly IAuthService _authService = authService;
        private readonly IUserService _userService = userService;

        [HttpPost]
        [EnableRateLimiting("Sliding")]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var existingUser = await _userService.GetByUsername(request.Username);
            if (existingUser != null)
                return Conflict(new { message = "Username already exists." });

            var user = await _authService.CreateUser(request.Username, request.Password, request.Email, request.DisplayName);
            return Ok(new
            {
                message = "User registered successfully.",
                user = new
                {
                    user.UID,
                    user.UUID,
                    user.Username,
                    user.Email,
                    user.DisplayName,
                    user.Roles
                }
            }
            );
        }
        [HttpPost]
        [Route("login")]
        [EnableRateLimiting("Sliding")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) && string.IsNullOrEmpty(request.Email))
                return BadRequest(new { message = "Username or email is required." });

            User? user = null;
            if (!string.IsNullOrEmpty(request.Username))
                user = await _userService.GetByUsername(request.Username);
            if (user == null && !string.IsNullOrEmpty(request.Email))
                user = await _userService.GetByEmail(request.Email);

            if (user == null) return BadRequest(new { message = "Invalid username/email or password." });
            if (!Bcrypt.Verify(request.Password, user.PasswordHash))
                return BadRequest(new { message = "Invalid username/email or password." });
            var token = _authService.GenerateJWTToken(user);
            return Ok(new { token });
        }
        [HttpPost]
        [Route("refresh")]
        [EnableRateLimiting("Sliding")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var jwtResult = await _authService.RefreshJWTToken(request.Token, request.RefreshToken);
                return Ok(new { token = jwtResult });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}
