using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.DTOs.ApiKey;
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
        ApiKeyService apiKeyService,
        IOptions<AuthSettings> options,
        VerificationService verification,
        TotpVerificationProvider totp,
        AppDbContext db
    ) : ControllerBase
    {
        private readonly AuthService _authService = authService;
        private readonly UserService _userService = userService;
        private readonly ApiKeyService _apiKeyService = apiKeyService;
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

            var normalizedEmail = UserService.NormalizeEmail(request.Email);
            if (normalizedEmail != null)
            {
                var existingEmailUser = await _userService.GetByEmail(normalizedEmail);
                if (existingEmailUser != null)
                    return Conflict(new { success = false, message = "Email already in use." });
            }
            if (!string.IsNullOrEmpty(request.DisplayName) && request.DisplayName.Length > 26)
                return BadRequest(new { success = false, message = "Display name should not exceed 26 characters." });

            User user;
            try
            {
                user = await _authService.CreateUser(request.Username, request.Password, normalizedEmail, request.DisplayName);
            }
            catch (DbUpdateException)
            {
                if (await _userService.GetByUsername(request.Username) != null)
                    return Conflict(new { success = false, message = "Username already exists." });

                if (normalizedEmail != null && await _userService.GetByEmail(normalizedEmail) != null)
                    return Conflict(new { success = false, message = "Email already in use." });

                throw;
            }

            if (!string.IsNullOrWhiteSpace(user.Email))
                await _authService.SendEmailVerification(user);

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
                        IsBanned = user.IsBanned,
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
                    admins_require_2fa = authSettings.Admins_Require_2FA,
                }
            );
        }

        [HttpGet]
        [Authorize(Policy = "JwtOnly")]
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
        [Authorize(Policy = "JwtOnly")]
        [Route("totp/enable")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> EnableTotp([FromBody] EnableTotpDto request)
        {
            var uuid = Guid.Parse(User.FindFirst("uuid")!.Value);
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
        [Authorize(Policy = "JwtOnly")]
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

        [HttpPost]
        [Authorize(Policy = "JwtOnly")]
        [Route("apikey/create")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> CreateApiKey([FromBody] CreateApiKeyRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Name))
                return BadRequest(new { success = false, message = "API key name is required." });
            if (request.Name.Length > 26)
                return BadRequest(new { success = false, message = "API key name must not exceed 26 characters." });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });

            var existingKeys = await _apiKeyService.GetUserKeysAsync(user.UUID);
            if (existingKeys.Count >= 10)
                return BadRequest(new { success = false, message = "API key limit reached. Please delete existing keys before creating new ones." });

            var (apiKey, key) = await _apiKeyService.CreateAsync(user.UUID, request.Name);

            return Ok(
                new
                {
                    success = true,
                    message = "API key created. Save it now as you won't be able to see it again.",
                    apiKey = new ApiKeyResponseDto
                    {
                        UUID = apiKey.UUID,
                        Key = key,
                        Name = apiKey.Name,
                        CreatedAt = apiKey.CreatedAt,
                    },
                }
            );
        }

        [HttpGet]
        [Authorize]
        [Route("apikey/list")]
        public async Task<IActionResult> ListApiKeys()
        {
            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });

            var apiKeys = await _apiKeyService.GetUserKeysAsync(user.UUID);
            return Ok(
                new
                {
                    success = true,
                    apiKeys = apiKeys
                        .Select(k => new ApiKeyListItemDto
                        {
                            UUID = k.UUID,
                            Name = k.Name,
                            CreatedAt = k.CreatedAt,
                            LastUsedAt = k.LastUsedAt,
                        })
                        .ToList(),
                }
            );
        }

        [HttpDelete]
        [Authorize(Policy = "JwtOnly")]
        [Route("apikey/{uuid}")]
        public async Task<IActionResult> DeleteApiKey(string uuid)
        {
            if (!Guid.TryParse(uuid, out var keyUUID))
                return BadRequest(new { success = false, message = "Invalid API key UUID." });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });

            var deleted = await _apiKeyService.DeleteAsync(user.UUID, keyUUID);
            if (!deleted)
                return NotFound(new { success = false, message = "API key not found." });

            return Ok(new { success = true, message = "API key deleted." });
        }

        [HttpGet]
        [Route("verify-email")]
        public async Task<IActionResult> VerifyEmail(string token)
        {
            (bool verifiedEmail, string message) = await _authService.VerifyEmailVerificationToken(token);
            if (verifiedEmail)
                return Ok(new { success = true, message });
            else
                return BadRequest(new { success = false, message });
        }

        [HttpPost]
        [EnableRateLimiting("Strict")]
        [Route("password/forgot")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (!await _verification.VerifyAsync(new VerificationContext { Token = request.Token, Ip = HttpContext.GetRequestIP() }))
                return BadRequest(new { success = false, message = "Verification failed." });

            var result = await _authService.RequestPasswordResetForEmail(request.Email);
            if (!result.success)
                return Ok(new { success = true, message = "If an account exists for that email, a reset link has been sent." });

            return Ok(new { success = true, message = result.message });
        }

        [HttpGet]
        [Route("password/reset-info")]
        public async Task<IActionResult> GetPasswordResetInfo([FromQuery] string token)
        {
            var info = await _authService.GetPasswordResetTokenInfo(token);
            if (!info.success || info.user == null)
                return BadRequest(new { success = false, message = info.message });
            if (info.blocked)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            return Ok(
                new
                {
                    success = true,
                    username = info.username,
                    requiresTotp = info.requiresTotp,
                }
            );
        }

        [HttpPost]
        [Route("password/reset")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ResetPassword([FromBody] PasswordResetDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.ResetPasswordWithToken(request.Token, request.NewPassword, request.TotpCode);
            if (!result.success)
            {
                if (result.message == "2FA is required to perform this action.")
                    return StatusCode(403, new { success = false, message = result.message });
                return BadRequest(new { success = false, message = result.message });
            }

            return Ok(new { success = true, message = result.message });
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [Route("password/change")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ChangePassword([FromBody] PasswordChangeDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });

            var result = await _authService.ChangeOwnPassword(user, request.CurrentPassword, request.NewPassword, request.TotpCode);
            if (!result.success)
            {
                if (result.message == "2FA is required to perform this action.")
                    return StatusCode(403, new { success = false, message = result.message });
                return BadRequest(new { success = false, message = result.message });
            }

            return Ok(new { success = true, message = result.message });
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [Route("password/admin-reset-link/{uuid}")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> AdminGeneratePasswordResetLink(Guid uuid, [FromBody] AdminPasswordResetLinkDto request)
        {
            var jwtUser = HttpContext.GetJwtUser()!;
            if (!jwtUser.Roles.HasFlag(Role.Admin))
                return StatusCode(403, new { success = false, message = "You do not have permission to perform this action." });

            var targetUser = await _userService.GetByUUID(uuid);
            if (targetUser == null)
                return NotFound(new { success = false, message = "User not found." });

            if (jwtUser.TotpEnabled)
            {
                if (
                    string.IsNullOrWhiteSpace(request.TotpCode)
                    || !await _totp.VerifyAsync(new VerificationContext { UserUUID = jwtUser.UUID, Code = request.TotpCode })
                )
                {
                    return Unauthorized(new { success = false, message = "Invalid TOTP code." });
                }
            }
            else if (options.Value.Admins_Require_2FA)
            {
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });
            }

            var result = await _authService.GeneratePasswordResetLink(targetUser, sendEmail: !string.IsNullOrWhiteSpace(targetUser.Email));
            if (!result.success)
            {
                if (result.retryAfter.HasValue)
                {
                    Response.Headers.RetryAfter = Math.Ceiling(result.retryAfter.Value / 1000d).ToString();
                    return StatusCode(
                        StatusCodes.Status429TooManyRequests,
                        new
                        {
                            success = false,
                            message = result.message,
                            retryAfter = result.retryAfter,
                        }
                    );
                }

                return BadRequest(
                    new
                    {
                        success = false,
                        message = result.message,
                        retryAfter = result.retryAfter,
                    }
                );
            }

            return Ok(
                new
                {
                    success = true,
                    message = result.message,
                    resetLink = result.resetLink,
                }
            );
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnly")]
        [EnableRateLimiting("Sensitive")]
        [Route("email/resend-verification")]
        public async Task<IActionResult> ResendEmailVerification()
        {
            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });

            var result = await _authService.ResendEmailVerification(user);
            if (!result.success)
            {
                if (result.retryAfter.HasValue)
                {
                    Response.Headers.RetryAfter = Math.Ceiling(result.retryAfter.Value / 1000d).ToString();
                    return StatusCode(
                        StatusCodes.Status429TooManyRequests,
                        new
                        {
                            success = false,
                            message = result.message,
                            retryAfter = result.retryAfter,
                        }
                    );
                }

                return BadRequest(
                    new
                    {
                        success = false,
                        message = result.message,
                        retryAfter = result.retryAfter,
                    }
                );
            }

            return Ok(new { success = true, message = result.message });
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnly")]
        [EnableRateLimiting("Sensitive")]
        [Route("email/change")]
        public async Task<IActionResult> ChangeEmail([FromBody] ChangeEmailDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return BadRequest(new { success = false, message = "User not found." });

            var totpEnabled = await _db.UserTotps.AnyAsync(t => t.UserUUID == user.UUID);
            if (totpEnabled)
            {
                if (
                    string.IsNullOrWhiteSpace(request.TotpCode)
                    || !await _totp.VerifyAsync(new VerificationContext { UserUUID = user.UUID, Code = request.TotpCode })
                )
                {
                    return Unauthorized(new { success = false, message = "Invalid TOTP code." });
                }
            }

            var result = await _authService.RequestEmailChange(user, request.Email);
            if (!result.success)
            {
                if (result.retryAfter.HasValue)
                {
                    Response.Headers.RetryAfter = Math.Ceiling(result.retryAfter.Value / 1000d).ToString();
                    return StatusCode(
                        StatusCodes.Status429TooManyRequests,
                        new
                        {
                            success = false,
                            message = result.message,
                            retryAfter = result.retryAfter,
                        }
                    );
                }

                return BadRequest(
                    new
                    {
                        success = false,
                        message = result.message,
                        retryAfter = result.retryAfter,
                    }
                );
            }

            return Ok(new { success = true, message = result.message });
        }
    }
}
