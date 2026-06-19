using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.DTOs.Auth;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Services.Verification.Providers;
using SharpbinV3.Server.Settings;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV3.Server.Services
{
    public class JwtUser
    {
        public Guid UUID { get; set; }
        public string Username { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public bool TotpEnabled { get; set; }
        public Role Roles { get; set; }
        public bool IsBanned { get; set; }
        public DateTime Expires { get; set; }
    }

    public sealed class AuthService(
        AppDbContext db,
        EmailService email,
        TotpVerificationProvider totp,
        IOptions<JWTSettings> jwtOptions,
        IOptions<AuthSettings> authOptions,
        IOptions<AppSettings> appSettings,
        ILogger<AuthService> logger
    )
    {
        private readonly AppDbContext _db = db;
        private readonly EmailService _email = email;
        private readonly TotpVerificationProvider _totp = totp;
        private readonly JWTSettings _jwtSettings = jwtOptions.Value;
        private readonly AuthSettings _authSettings = authOptions.Value;
        private readonly AppSettings _appSettings = appSettings.Value;
        private readonly ILogger _logger = logger;
        private const int EmailVerificationTokenLength = 64;
        private static readonly TimeSpan EmailActionCooldown = TimeSpan.FromHours(12);
        private static readonly TimeSpan EmailVerificationLifetime = TimeSpan.FromDays(1);
        private static readonly TimeSpan PasswordResetLifetime = TimeSpan.FromDays(1);

        public async Task<User> CreateUser(string username, string password, string? email, string? displayName)
        {
            var user = new User
            {
                Username = UserService.NormalizeUsername(username),
                PasswordHash = Bcrypt.HashPassword(password),
                Email = UserService.NormalizeEmail(email),
                DisplayName = displayName,
                UUID = Guid.CreateVersion7(),
            };

            if (_authSettings.First_User_Admin && !await _db.Users.AnyAsync())
                user.Roles = Role.User | Role.Admin;

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task<CreateJWT> GenerateJWTToken(User user)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);

            var totpEnabled = await _db.UserTotps.AnyAsync(t => t.UserUUID == user.UUID);
            var claims = new List<Claim>
            {
                new("uuid", user.UUID.ToString()),
                new("username", user.Username),
                new("displayname", user.DisplayName ?? ""),
                new("totp_enabled", totpEnabled.ToString()),
                new("roles", ((int)user.Roles).ToString()),
                new("is_banned", user.IsBanned.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            };

            var token = jwtHandler.CreateToken(descriptor);
            var jwtToken = jwtHandler.WriteToken(token);
            var jti = claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;

            var rawRefreshToken = Utilities.GenerateSecureRandomString(36) + Guid.NewGuid();
            var refreshToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserUUID = user.UUID,
                JwtId = jti,
                TokenHash = Utilities.ComputeSha256(rawRefreshToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMonths(6),
                Used = false,
                Revoked = false,
            };

            await _db.RefreshTokens.AddAsync(refreshToken);
            await _db.SaveChangesAsync();

            return new CreateJWT
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = rawRefreshToken,
            };
        }

        public async Task<CreateJWT> RefreshJWTToken(string token, string refreshToken)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);

            try
            {
                var principal = jwtHandler.ValidateToken(
                    token,
                    new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = true,
                        ValidIssuer = _jwtSettings.Issuer,
                        ValidateAudience = true,
                        ValidAudience = _jwtSettings.Audience,
                        ClockSkew = TimeSpan.Zero,
                        ValidateLifetime = false,
                        RequireSignedTokens = true,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    },
                    out SecurityToken validatedToken
                );

                var jti = principal.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
                var userUUID = principal.Claims.First(c => c.Type == "uuid").Value;
                var userGuid = Guid.Parse(userUUID);

                var tokenHash = Utilities.ComputeSha256(refreshToken);
                await using var transaction = await _db.Database.BeginTransactionAsync();
                var now = DateTimeOffset.UtcNow;
                var revokedCount = await _db.Database.ExecuteSqlInterpolatedAsync(
                    $"""
                    UPDATE RefreshTokens
                    SET Used = 1, Revoked = 1
                    WHERE TokenHash = {tokenHash}
                      AND Used = 0
                      AND Revoked = 0
                      AND ExpiresAt >= {now}
                      AND JwtId = {jti}
                      AND UserUUID = {userGuid}
                    """
                );

                if (revokedCount != 1)
                    return new CreateJWT { Success = false, Errors = ["Invalid or expired refresh token."] };

                var user = await _db.Users.FirstOrDefaultAsync(u => u.UUID == userGuid);
                if (user == null)
                    return new CreateJWT { Success = false, Errors = ["Invalid token."] };

                var newTokenResult = await GenerateJWTToken(user);
                if (!newTokenResult.Success)
                    return newTokenResult;

                await transaction.CommitAsync();

                return newTokenResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing JWT token");
                return new CreateJWT { Success = false, Errors = ["Server Error"] };
            }
        }

        public async Task<User> UpdateUser(User user)
        {
            var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.UUID == user.UUID) ?? throw new Exception("User not found");
            existingUser.Username = UserService.NormalizeUsername(user.Username);
            existingUser.Email = UserService.NormalizeEmail(user.Email);
            existingUser.DisplayName = user.DisplayName;
            existingUser.Roles = user.Roles;
            existingUser.LastLogin = user.LastLogin;
            existingUser.Visibility = user.Visibility;
            _db.Users.Update(existingUser);
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task UpdateLoginTime(User user)
        {
            var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.UUID == user.UUID) ?? throw new Exception("User not found");
            existingUser.LastLogin = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _db.Users.Update(existingUser);
            await _db.SaveChangesAsync();
        }

        public async Task<(bool success, string message, long? retryAfter, string? resetLink)> GeneratePasswordResetLink(
            User user,
            bool sendEmail = true
        )
        {
            return await IssuePasswordResetTokenAsync(user, sendEmail: sendEmail, invalidateExisting: true, exposeLink: true);
        }

        public async Task<(bool success, string message, bool requiresTotp, bool blocked, string username, User? user)> GetPasswordResetTokenInfo(
            string token
        )
        {
            var tokenEntity = await GetValidPasswordResetToken(token);
            if (tokenEntity == null)
                return (false, "Token is expired or already used.", false, false, string.Empty, null);

            var user = tokenEntity.User;
            if (user == null)
                return (false, "Token is expired or already used.", false, false, string.Empty, null);

            var state = await GetPasswordResetTwoFactorState(user);
            return (true, "Token is valid.", state.requiresTotp, state.blocked, user.Username, user);
        }

        public async Task<(bool success, string message)> ChangeOwnPassword(User user, string currentPassword, string newPassword, string? totpCode)
        {
            if (!Bcrypt.Verify(currentPassword, user.PasswordHash))
                return (false, "Current password is incorrect.");

            var totpState = await GetPasswordResetTwoFactorState(user);
            if (totpState.blocked)
                return (false, "2FA is required to perform this action.");

            if (totpState.requiresTotp)
            {
                if (
                    string.IsNullOrWhiteSpace(totpCode) || !await _totp.VerifyAsync(new VerificationContext { UserUUID = user.UUID, Code = totpCode })
                )
                    return (false, "Invalid TOTP code.");
            }

            if (!RegisterUserDto.ValidatePassword().IsMatch(newPassword))
                return (false, "Password should have at least 8 characters, including uppercase, lowercase, and digits.");

            var originalEmail = user.Email;
            await using var transaction = await _db.Database.BeginTransactionAsync();
            await ReplacePasswordAsync(user, newPassword, saveChanges: false);
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            if (!string.IsNullOrWhiteSpace(originalEmail))
            {
                await _email.SendAsync(originalEmail, "Sharpbin Password Changed", EmailTemplates.PasswordChanged(user.Username));
            }

            return (true, "Password updated successfully.");
        }

        public async Task<(bool success, string message)> ResetPasswordWithToken(string token, string newPassword, string? totpCode)
        {
            if (!RegisterUserDto.ValidatePassword().IsMatch(newPassword))
                return (false, "Password should have at least 8 characters, including uppercase, lowercase, and digits.");

            var tokenEntity = await GetValidPasswordResetToken(token);
            if (tokenEntity == null || tokenEntity.User == null)
                return (false, "Token is expired or already used.");

            var user = tokenEntity.User;
            var totpState = await GetPasswordResetTwoFactorState(user);
            if (totpState.blocked)
                return (false, "2FA is required to perform this action.");

            if (totpState.requiresTotp)
            {
                if (
                    string.IsNullOrWhiteSpace(totpCode) || !await _totp.VerifyAsync(new VerificationContext { UserUUID = user.UUID, Code = totpCode })
                )
                    return (false, "Invalid TOTP code.");
            }

            await using var transaction = await _db.Database.BeginTransactionAsync();
            var originalEmail = user.Email;
            tokenEntity.Used = true;
            await ReplacePasswordAsync(user, newPassword, saveChanges: false);
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            if (!string.IsNullOrWhiteSpace(originalEmail))
            {
                await _email.SendAsync(originalEmail, "Sharpbin Password Changed", EmailTemplates.PasswordChanged(user.Username));
            }

            return (true, "Password reset successfully.");
        }

        public async Task<User?> GetUserFromHttpContext(HttpContext context)
        {
            var apiKey = context.GetApiKeyFromContext();
            if (apiKey != null)
                return await _db.Users.FirstOrDefaultAsync(u => u.UUID == apiKey.UserUUID);

            var uuidClaim = context.User.Claims.FirstOrDefault(c => c.Type == "uuid")?.Value;
            if (uuidClaim == null)
                return null;
            var userUUID = Guid.Parse(uuidClaim);
            return await _db.Users.FirstOrDefaultAsync(u => u.UUID == userUUID);
        }

        public async Task<(bool success, string message, long? retryAfter)> ResendEmailVerification(User user)
        {
            if (string.IsNullOrWhiteSpace(user.Email))
                return (false, "No email address is set for this account.", null);

            if (user.EmailVerified)
                return (false, "Email is already verified.", null);

            var cooldown = await GetEmailTokenCooldown(user.UUID, EmailTokenType.VerifyEmail);
            if (cooldown > TimeSpan.Zero)
                return (
                    false,
                    $"Please wait {Utilities.FormatDuration(cooldown)} before requesting another verification email.",
                    Utilities.TimeSpanToMilliseconds(cooldown)
                );

            await SendEmailVerification(user, invalidateExisting: true);
            return (true, "Verification email sent.", null);
        }

        public async Task<(bool success, string message, long? retryAfter)> RequestPasswordResetForEmail(string email)
        {
            var normalizedEmail = UserService.NormalizeEmail(email);
            if (normalizedEmail == null)
                return (true, "If an account exists for that email, a reset link has been sent.", null);

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
            if (user == null)
                return (true, "If an account exists for that email, a reset link has been sent.", null);

            await IssuePasswordResetTokenAsync(user, sendEmail: true, invalidateExisting: true, exposeLink: false);
            return (true, "If an account exists for that email, a reset link has been sent.", null);
        }

        public async Task<(bool success, string message, long? retryAfter)> RequestAccountDeletionVerification(User user)
        {
            if (string.IsNullOrWhiteSpace(user.Email) || !user.EmailVerified)
                return (false, "A verified email address is required for email deletion verification.", null);

            var cooldown = await GetEmailTokenCooldown(user.UUID, EmailTokenType.DeleteAccount);
            if (cooldown > TimeSpan.Zero)
                return (
                    false,
                    $"Please wait {Utilities.FormatDuration(cooldown)} before requesting another account deletion email.",
                    Utilities.TimeSpanToMilliseconds(cooldown)
                );

            await InvalidateActiveTokens(user.UUID, EmailTokenType.DeleteAccount);

            var token = Utilities.GenerateSecureRandomString(EmailVerificationTokenLength);
            var tokenHash = Utilities.ComputeSha256(token);
            var emailBody = EmailTemplates.DeleteAccountVerification(user.Username, token);

            await _email.SendAsync(user.Email, "Confirm Account Deletion - Sharpbin", emailBody);
            await _db.EmailVerificationTokens.AddAsync(
                new EmailVerificationToken
                {
                    TokenHash = tokenHash,
                    UserUUID = user.UUID,
                    User = user,
                    ExpiresAt = DateTimeOffset.UtcNow.Add(EmailVerificationLifetime).ToUnixTimeMilliseconds(),
                    Type = EmailTokenType.DeleteAccount,
                }
            );
            await _db.SaveChangesAsync();

            return (true, "Account deletion verification email sent.", null);
        }

        public async Task<bool> VerifyAccountDeletionToken(User user, string token)
        {
            if (token.Length != EmailVerificationTokenLength)
                return false;

            var tokenHash = Utilities.ComputeSha256(token);
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var tokenEntity = await _db.EmailVerificationTokens.FirstOrDefaultAsync(t =>
                t.UserUUID == user.UUID && t.TokenHash == tokenHash && t.Type == EmailTokenType.DeleteAccount && !t.Used && t.ExpiresAt >= now
            );

            if (tokenEntity == null)
                return false;

            tokenEntity.Used = true;
            await _db.SaveChangesAsync();
            return true;
        }

        public async Task SendAccountDeletedNotification(string email, string username)
        {
            if (string.IsNullOrWhiteSpace(email))
                return;

            await _email.SendAsync(email, "Sharpbin Account Deleted", EmailTemplates.AccountDeleted(username));
        }

        public async Task<(bool success, string message, long? retryAfter)> RequestEmailChange(User user, string requestedEmail)
        {
            var newEmail = UserService.NormalizeEmail(requestedEmail);
            if (newEmail == null)
                return (false, "Email is required.", null);

            if (string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase))
                return (false, "That email is already on your account.", null);

            var existingEmailUser = await _db.Users.FirstOrDefaultAsync(u => u.Email == newEmail && u.UUID != user.UUID);
            if (existingEmailUser != null)
                return (false, "Email already in use.", null);

            var cooldown = await GetEmailTokenCooldown(user.UUID, EmailTokenType.ChangeEmail);
            if (cooldown > TimeSpan.Zero)
                return (
                    false,
                    $"Please wait {Utilities.FormatDuration(cooldown)} before changing your email again.",
                    Utilities.TimeSpanToMilliseconds(cooldown)
                );

            await InvalidateActiveEmailTokens(user.UUID);

            var token = Utilities.GenerateSecureRandomString(EmailVerificationTokenLength);
            var tokenHash = Utilities.ComputeSha256(token);
            var verificationUrl = BuildVerificationUrl(token);
            var emailBody = EmailTemplates.VerifyChangedEmail(verificationUrl, user.Username);

            await _email.SendAsync(newEmail, "Verify Your New Email - Sharpbin", emailBody);

            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                var notificationBody = EmailTemplates.EmailChangeRequested(user.Username, user.Email, newEmail);
                await _email.SendAsync(user.Email, "Sharpbin Email Change Requested", notificationBody);
            }

            var verificationToken = new EmailVerificationToken
            {
                TokenHash = tokenHash,
                UserUUID = user.UUID,
                User = user,
                TargetEmail = newEmail,
                ExpiresAt = DateTimeOffset.UtcNow.Add(EmailVerificationLifetime).ToUnixTimeMilliseconds(),
                Type = EmailTokenType.ChangeEmail,
            };
            await _db.EmailVerificationTokens.AddAsync(verificationToken);
            await _db.SaveChangesAsync();

            return (true, "Verification email sent to the new address.", null);
        }

        public async Task SendEmailVerification(User user, bool invalidateExisting = true)
        {
            if (string.IsNullOrWhiteSpace(user.Email))
                return;

            if (invalidateExisting)
                await InvalidateActiveEmailTokens(user.UUID);

            string token = Utilities.GenerateSecureRandomString(EmailVerificationTokenLength);
            string tokenHash = Utilities.ComputeSha256(token);

            string verificationUrl = BuildVerificationUrl(token);
            string emailBody = EmailTemplates.VerifyEmail(verificationUrl, user.Username);

            await _email.SendAsync(user.Email, "Verify Your Email - Sharpbin", emailBody);
            var verificationToken = new EmailVerificationToken
            {
                TokenHash = tokenHash,
                UserUUID = user.UUID,
                User = user,
                ExpiresAt = DateTimeOffset.UtcNow.Add(EmailVerificationLifetime).ToUnixTimeMilliseconds(),
                Type = EmailTokenType.VerifyEmail,
            };
            await _db.EmailVerificationTokens.AddAsync(verificationToken);
            await _db.SaveChangesAsync();
        }

        public async Task<(bool success, string message, long? retryAfter, string? resetLink)> IssuePasswordResetTokenAsync(
            User user,
            bool sendEmail,
            bool invalidateExisting,
            bool exposeLink
        )
        {
            if (string.IsNullOrWhiteSpace(user.Email) && sendEmail)
                return (false, "No email address is set for this account.", null, null);

            var cooldown = await GetEmailTokenCooldown(user.UUID, EmailTokenType.ResetPassword);
            if (cooldown > TimeSpan.Zero)
                return (
                    false,
                    $"Please wait {Utilities.FormatDuration(cooldown)} before requesting another password reset link.",
                    Utilities.TimeSpanToMilliseconds(cooldown),
                    null
                );

            if (invalidateExisting)
                await InvalidateActiveTokens(user.UUID, EmailTokenType.ResetPassword);

            var token = Utilities.GenerateSecureRandomString(EmailVerificationTokenLength);
            var tokenHash = Utilities.ComputeSha256(token);
            var resetLink = BuildResetPasswordUrl(token);

            if (sendEmail && !string.IsNullOrWhiteSpace(user.Email))
            {
                var emailBody = EmailTemplates.ResetPassword(user.Username, resetLink);
                await _email.SendAsync(user.Email, "Reset Your Password - Sharpbin", emailBody);
            }

            var verificationToken = new EmailVerificationToken
            {
                TokenHash = tokenHash,
                UserUUID = user.UUID,
                User = user,
                ExpiresAt = DateTimeOffset.UtcNow.Add(PasswordResetLifetime).ToUnixTimeMilliseconds(),
                Type = EmailTokenType.ResetPassword,
            };
            await _db.EmailVerificationTokens.AddAsync(verificationToken);
            await _db.SaveChangesAsync();

            return (true, sendEmail ? "Password reset email sent." : "Password reset link generated.", null, exposeLink ? resetLink : null);
        }

        public async Task<(bool success, string message)> VerifyEmailVerificationToken(string token)
        {
            if (token.Length != EmailVerificationTokenLength)
                return (false, "Invalid token.");

            string tokenHash = Utilities.ComputeSha256(token);
            var verificationToken = await _db.EmailVerificationTokens.Include(t => t.User).FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

            if (
                verificationToken == null
                || verificationToken.User == null
                || verificationToken.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                || verificationToken.Used
            )
                return (false, "Token is expired or already used.");

            if (verificationToken != null && !verificationToken.Used)
            {
                if (verificationToken.Type == EmailTokenType.ChangeEmail)
                {
                    if (string.IsNullOrWhiteSpace(verificationToken.TargetEmail))
                        return (false, "Token is invalid.");

                    var normalizedTargetEmail = UserService.NormalizeEmail(verificationToken.TargetEmail);
                    if (normalizedTargetEmail == null)
                        return (false, "Token is invalid.");

                    var existingEmailUser = await _db.Users.FirstOrDefaultAsync(u =>
                        u.Email == normalizedTargetEmail && u.UUID != verificationToken.UserUUID
                    );
                    if (existingEmailUser != null)
                        return (false, "Email already in use.");

                    if (!string.IsNullOrWhiteSpace(verificationToken.User.Email))
                    {
                        var notificationBody = EmailTemplates.EmailChanged(
                            verificationToken.User.Username,
                            verificationToken.User.Email,
                            normalizedTargetEmail
                        );
                        await _email.SendAsync(verificationToken.User.Email, "Sharpbin Email Address Changed", notificationBody);
                    }

                    verificationToken.User.Email = normalizedTargetEmail;
                }

                verificationToken.Used = true;
                verificationToken.User.EmailVerified = true;
                await InvalidateActiveEmailTokens(verificationToken.UserUUID);
                await _db.SaveChangesAsync();
            }

            await _db.SaveChangesAsync();
            return (true, "Email successfully verified.");
        }

        private async Task ReplacePasswordAsync(User user, string newPassword, bool saveChanges = true)
        {
            var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.UUID == user.UUID) ?? throw new Exception("User not found");
            existingUser.PasswordHash = Bcrypt.HashPassword(newPassword);

            await _db
                .RefreshTokens.Where(rt => rt.UserUUID == user.UUID && !rt.Revoked)
                .ExecuteUpdateAsync(setters => setters.SetProperty(rt => rt.Revoked, true).SetProperty(rt => rt.Used, true));

            await InvalidateActiveTokens(user.UUID, EmailTokenType.ResetPassword);
            _db.Users.Update(existingUser);
            if (saveChanges)
                await _db.SaveChangesAsync();
        }

        private async Task<EmailVerificationToken?> GetValidPasswordResetToken(string token)
        {
            if (token.Length != EmailVerificationTokenLength)
                return null;

            var tokenHash = Utilities.ComputeSha256(token);
            return await _db
                .EmailVerificationTokens.Include(t => t.User)
                .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && t.Type == EmailTokenType.ResetPassword);
        }

        private async Task<(bool requiresTotp, bool blocked)> GetPasswordResetTwoFactorState(User user)
        {
            var totpEnabled = await _db.UserTotps.AnyAsync(t => t.UserUUID == user.UUID);
            var blocked = user.Roles.HasFlag(Role.Admin) && _authSettings.Admins_Require_2FA && !totpEnabled;
            return (totpEnabled, blocked);
        }

        private async Task InvalidateActiveTokens(Guid userUUID, params EmailTokenType[] types)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var tokenTypes = types.Length > 0 ? types : [EmailTokenType.VerifyEmail, EmailTokenType.ChangeEmail, EmailTokenType.ResetPassword];
            await _db
                .EmailVerificationTokens.Where(t => t.UserUUID == userUUID && !t.Used && t.ExpiresAt >= now && tokenTypes.Contains(t.Type))
                .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.Used, true));
        }

        private async Task InvalidateActiveEmailTokens(Guid userUUID)
        {
            await InvalidateActiveTokens(userUUID, EmailTokenType.VerifyEmail, EmailTokenType.ChangeEmail);
        }

        private async Task InvalidateActivePasswordResetTokens(Guid userUUID)
        {
            await InvalidateActiveTokens(userUUID, EmailTokenType.ResetPassword);
        }

        private async Task<TimeSpan> GetEmailTokenCooldown(Guid userUUID, EmailTokenType type)
        {
            var lastCreatedAt = await _db
                .EmailVerificationTokens.Where(t => t.UserUUID == userUUID && t.Type == type)
                .OrderByDescending(t => t.CreatedAt)
                .Select(t => (long?)t.CreatedAt)
                .FirstOrDefaultAsync();

            if (lastCreatedAt == null)
                return TimeSpan.Zero;

            var nextAllowedAt = DateTimeOffset.FromUnixTimeMilliseconds(lastCreatedAt.Value).Add(EmailActionCooldown);
            var remaining = nextAllowedAt - DateTimeOffset.UtcNow;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        private string BuildVerificationUrl(string token) =>
            $"{(_appSettings.Https ? "https" : "http")}://{_appSettings.Domain}/verify-email?token={token}";

        private string BuildResetPasswordUrl(string token) =>
            $"{(_appSettings.Https ? "https" : "http")}://{_appSettings.Domain}/reset-password?token={token}";
    }
}
