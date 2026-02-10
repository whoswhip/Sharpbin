using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.DTOs.Auth;
using SharpbinV3.Server.DTOs.User;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Services.Verification.Providers;
using SharpbinV3.Server.Settings;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV3.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(
        UserService userService,
        AuthService authService,
        IOptions<AuthSettings> options,
        VerificationService verification,
        TotpVerificationProvider totp,
        AppDbContext db
    ) : ControllerBase
    {
        private readonly AuthService _authService = authService;
        private readonly UserService _userService = userService;
        private readonly VerificationService _verification = verification;
        private readonly TotpVerificationProvider _totp = totp;
        private readonly AppDbContext _db = db;

        [HttpPost]
        [EnableRateLimiting("Strict")]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto request)
        {
            if (!options.Value.Registration_Enabled)
                return BadRequest(new { success = false, message = "Registration is disabled." });
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            if (!await _verification.VerifyAsync(new VerificationContext { Token = request.Token, Ip = HttpContext.GetRequestIP() }))
                return BadRequest(new { success = false, message = "Verification failed." });

            var existingUser = await _userService.GetByUsername(request.Username);
            if (existingUser != null)
                return Conflict(new { success = false, message = "Username already exists." });
            if (!string.IsNullOrEmpty(request.Email))
            {
                var existingEmailUser = await _userService.GetByEmail(request.Email);
                if (existingEmailUser != null)
                    return Conflict(new { success = false, message = "Email already in use." });
            }
            if (!string.IsNullOrEmpty(request.DisplayName) && request.DisplayName.Length > 26)
                return BadRequest(new { success = false, message = "Display name should not exceed 26 characters." });

            var user = await _authService.CreateUser(request.Username, request.Password, request.Email, request.DisplayName);
            return Ok(
                new
                {
                    message = "User registered successfully.",
                    user = new UserResponseDto
                    {
                        UID = user.UID,
                        UUID = user.UUID,
                        Username = user.Username,
                        DisplayName = user.DisplayName,
                        Email = user.Email,
                        Roles = user.Roles,
                        Visibility = user.Visibility,
                        LastLogin = user.LastLogin,
                    },
                }
            );
        }

        [HttpPost]
        [Route("login")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> Login([FromBody] LoginUserDto request)
        {
            if (string.IsNullOrEmpty(request.Username) && string.IsNullOrEmpty(request.Email))
                return BadRequest(new { success = false, message = "Username or email is required." });

            if (!await _verification.VerifyAsync(new VerificationContext { Token = request.Token, Ip = HttpContext.GetRequestIP() }))
                return BadRequest(new { success = false, message = "Verification failed." });

            User? user = null;
            if (!string.IsNullOrEmpty(request.Username))
                user = await _userService.GetByUsername(request.Username);
            if (user == null && !string.IsNullOrEmpty(request.Email))
                user = await _userService.GetByEmail(request.Email);

            if (user == null || !Bcrypt.Verify(request.Password, user.PasswordHash))
                return BadRequest(new { success = false, message = "Invalid username/email or password." });

            var totpEnabled = await _db.UserTotps.AnyAsync(t => t.UserUUID == user.UUID);
            if (totpEnabled)
            {
                if (string.IsNullOrWhiteSpace(request.TotpCode))
                    return BadRequest(new { success = false, message = "TOTP code is required." });

                var totpValid = await _totp.VerifyAsync(new VerificationContext { UserUUID = user.UUID, Code = request.TotpCode });

                if (!totpValid)
                    return BadRequest(new { success = false, message = "Invalid TOTP code." });
            }
            var token = _authService.GenerateJWTToken(user);
            await _authService.UpdateLoginTime(user);
            var result = await token;
            return Ok(
                new LoginResponseDto
                {
                    Success = true,
                    Token = result.Token ?? string.Empty,
                    RefreshToken = result.RefreshToken ?? string.Empty,
                }
            );
        }

        [HttpPost]
        [Route("refresh")]
        [EnableRateLimiting("Sliding")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto request)
        {
            try
            {
                var jwtResult = await _authService.RefreshJWTToken(request.Token, request.RefreshToken);
                return Ok(
                    new TokenRefreshResponseDto
                    {
                        Success = jwtResult?.Success ?? false,
                        Message =
                            jwtResult?.Errors != null && jwtResult.Errors.Count > 0
                                ? string.Join("; ", jwtResult.Errors)
                                : "Token refreshed successfully.",
                        Token = jwtResult != null ? new TokenData { Token = jwtResult.Token, RefreshToken = jwtResult.RefreshToken } : null,
                    }
                );
            }
            catch (Exception ex)
            {
                return BadRequest(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        [EnableRateLimiting("NoLimit")]
        [Route("info")]
        public IActionResult GetSiteInfo()
        {
            var authSettings = options.Value;
            return Ok(
                new
                {
                    cf_turnstile_site_key = string.IsNullOrEmpty(authSettings.CF_Turnstile_SiteKey) ? null : authSettings.CF_Turnstile_SiteKey,
                    registration_enabled = authSettings.Registration_Enabled,
                }
            );
        }

        [HttpGet]
        [Authorize]
        [Route("totp/enroll")]
        public async Task<IActionResult> StartTotpEnrollment()
        {
            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user is null)
                return BadRequest(new { success = false, message = "User not found." });

            var secret = _totp.GenerateSecret();
            var secretBase32 = _totp.ToBase32(secret);
            var account = string.IsNullOrWhiteSpace(user.Email) ? user.Username : user.Email!;
            var uri = _totp.BuildOtpAuthUri("SharpbinV3", account, secretBase32);
            return Ok(
                new
                {
                    success = true,
                    secret = secretBase32,
                    otpauth = uri,
                }
            );
        }

        [HttpPost]
        [Authorize]
        [Route("totp/enable")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> EnableTotp([FromBody] EnableTotpDto request)
        {
            var uuidClaim = User.Claims.FirstOrDefault(c => c.Type == "UUID")?.Value;
            if (string.IsNullOrEmpty(uuidClaim))
                return Unauthorized(new { success = false, message = "Invalid token." });

            var uuid = Guid.Parse(uuidClaim);
            if (string.IsNullOrWhiteSpace(request.Secret) || string.IsNullOrWhiteSpace(request.Code))
                return BadRequest(new { success = false, message = "Secret and code are required." });

            if (!_totp.VerifyWithSecretBase32(request.Secret, request.Code))
                return BadRequest(new { success = false, message = "Invalid TOTP code." });

            var secretBytes = _totp.FromBase32(request.Secret);
            var protectedBytes = _totp.Protect(secretBytes);
            var existing = await _db.UserTotps.FirstOrDefaultAsync(t => t.UserUUID == uuid);
            if (existing is null)
            {
                var entry = new UserTotp { UserUUID = uuid, EncryptedSecret = protectedBytes };
                _db.UserTotps.Add(entry);
            }
            else
            {
                existing.EncryptedSecret = protectedBytes;
                _db.UserTotps.Update(existing);
            }
            await _db.SaveChangesAsync();
            return Ok(new { success = true, message = "TOTP enabled." });
        }

        [HttpPost]
        [Authorize]
        [Route("totp/disable")]
        public async Task<IActionResult> DisableTotp([FromBody] DisableTotpDto dto)
        {
            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });
            if (string.IsNullOrWhiteSpace(dto.Code))
                return BadRequest(new { success = false, message = "TOTP code is required." });
            var existing = await _db.UserTotps.FirstOrDefaultAsync(t => t.UserUUID == user.UUID);
            if (existing is null)
                return BadRequest(new { success = false, message = "TOTP is not enabled." });
            if (!_totp.VerifyAsync(new VerificationContext { UserUUID = user.UUID, Code = dto.Code }).Result)
                return BadRequest(new { success = false, message = "Invalid TOTP code." });

            _db.UserTotps.Remove(existing);
            await _db.SaveChangesAsync();
            return Ok(new { success = true, message = "TOTP disabled." });
        }
    }
}
