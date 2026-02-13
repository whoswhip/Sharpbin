using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs.Auth;
using SharpbinV3.Server.Extensions;
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
        public int[] Roles { get; set; } = [];
        public DateTime Expires { get; set; }
    }

    public sealed class AuthService(
        AppDbContext db,
        IOptions<JWTSettings> jwtOptions,
        IOptions<AuthSettings> authOptions,
        ILogger<AuthService> logger
    )
    {
        private readonly AppDbContext _db = db;
        private readonly JWTSettings _jwtSettings = jwtOptions.Value;
        private readonly AuthSettings _authSettings = authOptions.Value;
        private readonly ILogger _logger = logger;

        public async Task<User> CreateUser(string username, string password, string? email, string? displayName)
        {
            var user = new User
            {
                Username = username,
                PasswordHash = Bcrypt.HashPassword(password),
                Email = email,
                DisplayName = displayName,
                UUID = Guid.CreateVersion7(),
            };

            if (_authSettings.First_User_Admin && !await _db.Users.AnyAsync())
                user.Roles = [0, 1, 255];

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
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            if (user.Roles != null)
            {
                foreach (var role in user.Roles)
                    claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.Role, "0"));
            }

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

            var rawRefreshToken = Utilities.GenerateRandomString(36) + Guid.NewGuid();
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

                var tokenHash = Utilities.ComputeSha256(refreshToken);

                var storedToken = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

                if (
                    storedToken == null
                    || storedToken.Used
                    || storedToken.Revoked
                    || storedToken.ExpiresAt < DateTimeOffset.UtcNow
                    || storedToken.JwtId != jti
                )
                {
                    return new CreateJWT { Success = false, Errors = ["Invalid or expired refresh token."] };
                }

                storedToken.Used = true;
                storedToken.Revoked = true;

                await _db.SaveChangesAsync();

                var userUUID = principal.Claims.First(c => c.Type == "uuid").Value;
                var user = await _db.Users.FirstOrDefaultAsync(u => u.UUID == Guid.Parse(userUUID));

                if (user == null || storedToken.UserUUID != Guid.Parse(userUUID))
                    return new CreateJWT { Success = false, Errors = ["Invalid token."] };

                return await GenerateJWTToken(user);
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
            existingUser.Username = user.Username;
            existingUser.Email = user.Email;
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
    }
}
