using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Settings;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV3.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(UserService userService, AuthService authService, IOptions<AuthSettings> options, VerificationService verification) : ControllerBase
    {
        private readonly AuthService _authService = authService;
        private readonly UserService _userService = userService;
        private readonly VerificationService _verification = verification;

        [HttpPost]
        [EnableRateLimiting("Sliding")]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!options.Value.Registration_Enabled)
                return BadRequest(new { message = "Registration is disabled." });
            if (!await _verification.VerifyAsync(request.Token, Utilities.GetRequestIP(HttpContext)))
                return BadRequest(new { message = "Verification failed." });

            var existingUser = await _userService.GetByUsername(request.Username);
            if (existingUser != null)
                return Conflict(new { message = "Username already exists." });
            if (!string.IsNullOrEmpty(request.Email))
            {
                var existingEmailUser = await _userService.GetByEmail(request.Email);
                if (existingEmailUser != null)
                    return Conflict(new { message = "Email already in use." });
            }
            if (!string.IsNullOrEmpty(request.DisplayName) && request.DisplayName.Length > 26)
                return BadRequest(new { message = "Display name should not exceed 26 characters." });

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

            if (!await _verification.VerifyAsync(request.Token, Utilities.GetRequestIP(HttpContext)))
                return BadRequest(new { message = "Verification failed." });

            User? user = null;
            if (!string.IsNullOrEmpty(request.Username))
                user = await _userService.GetByUsername(request.Username);
            if (user == null && !string.IsNullOrEmpty(request.Email))
                user = await _userService.GetByEmail(request.Email);

            if (user == null) return BadRequest(new { message = "Invalid username/email or password." });
            if (!Bcrypt.Verify(request.Password, user.PasswordHash))
                return BadRequest(new { message = "Invalid username/email or password." });
            var token = _authService.GenerateJWTToken(user);
            await _authService.UpdateLoginTime(user);
            return Ok(new { token.Result });
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

        [HttpGet]
        [Route("info")]
        public async Task<IActionResult> GetSiteInfo()
        {
            var authSettings = options.Value;
            return Ok(new
            {
                cf_turnstile_site_key = string.IsNullOrEmpty(authSettings.CF_Turnstile_SiteKey) ? null : authSettings.CF_Turnstile_SiteKey,
                registration_enabled = authSettings.Registration_Enabled
            });
        }
    }
}
