using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.Settings;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV3.Server.Services
{
    public sealed class AuthService(AppDbContext db, IOptions<JWTSettings> options) : IAuthService
    {
        private readonly AppDbContext _db = db;
        private readonly JWTSettings _jwtSettings = options.Value;

        public async Task<User> CreateUser(string username, string password, string? email, string? displayName)
        {
            var user = new User
            {
                Username = username,
                PasswordHash = Bcrypt.HashPassword(password),
                Email = email,
                DisplayName = displayName,
                UUID = Guid.CreateVersion7()
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return user;
        }
        public async Task<JWTResult> GenerateJWTToken(User user)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);

            var claims = new List<Claim>
            {
                new("UUID", user.UUID.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
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
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                )
            };

            var token = jwtHandler.CreateToken(descriptor);
            var jwtToken = jwtHandler.WriteToken(token);

            var existingToken = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.UserUUID == user.UUID);

            if (existingToken != null)
            {
                existingToken.JwtId = token.Id;
                existingToken.Used = false;
                existingToken.CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                existingToken.ExpiresAt = DateTimeOffset.UtcNow.AddMonths(6).ToUnixTimeMilliseconds();
                existingToken.Token = Utilities.GenerateRandomString(36) + Guid.NewGuid();
                _db.RefreshTokens.Update(existingToken);
            }
            else
            {
                var refreshToken = new RefreshToken()
                {
                    JwtId = token.Id,
                    Used = false,
                    User = user,
                    UserUUID = user.UUID,
                    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ExpiresAt = DateTimeOffset.UtcNow.AddMonths(6).ToUnixTimeMilliseconds(),
                    Token = Utilities.GenerateRandomString(36) + Guid.NewGuid()
                };
                await _db.RefreshTokens.AddAsync(refreshToken);
            }

            await _db.SaveChangesAsync();

            return new JWTResult()
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = existingToken?.Token ?? (await _db.RefreshTokens.FirstAsync(rt => rt.UserUUID == user.UUID)).Token
            };
        }

        public async Task<JWTResult> RefreshJWTToken(string token, string refreshToken)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);
            try
            {
                var principal = jwtHandler.ValidateToken(token, new TokenValidationParameters
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
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                }, out SecurityToken validatedToken);
                var jwtId = validatedToken.Id;
                var storedRefreshToken = await _db.RefreshTokens
                    .FirstOrDefaultAsync(rt => rt.Token == refreshToken);
                if (storedRefreshToken == null
                    || storedRefreshToken.Used
                    || storedRefreshToken.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    || storedRefreshToken.JwtId != jwtId)
                {
                    return new JWTResult() { Success = false, Errors = ["Invalid refresh token, possibly already used or expired."] };
                }
                storedRefreshToken.Used = true;
                await _db.SaveChangesAsync();
                var userUUID = principal.Claims.First(c => c.Type == "UUID").Value;
                var user = await _db.Users.FirstOrDefaultAsync(u => u.UUID == Guid.Parse(userUUID));
                if (user == null || storedRefreshToken.UserUUID != Guid.Parse(userUUID))
                    return new JWTResult() { Success = false, Errors = ["Invalid token."] };

                return await GenerateJWTToken(user);
            }
            catch
            {
                return new JWTResult() { Success = false, Errors = ["Server Error"] };
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
    }
}
