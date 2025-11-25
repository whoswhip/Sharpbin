using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SharpbinV3.Data;
using SharpbinV3.Data.Entities;
using SharpbinV3.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV3.Services
{
    public sealed class AuthService(AppDbContext db, IConfiguration configuration) : IAuthService
    {
        private readonly AppDbContext _db = db;
        private readonly IConfiguration _configuration = configuration;

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
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:Secret"]!);

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim("UUID", user.UUID.ToString()),
                    new Claim("Roles", user.Roles != null ? string.Join(",", user.Roles) : "0"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                ]),
                Issuer = _configuration["JwtConfig:Issuer"],
                Audience = _configuration["JwtConfig:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
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

        public async Task<bool> ValidateJWTToken(string token)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:Secret"]!);
            try
            {
                jwtHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<JWTResult> RefreshJWTToken(string token, string refreshToken)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:Secret"]!);
            try
            {
                var principal = jwtHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["JwtConfig:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["JwtConfig:Audience"],
                    ClockSkew = TimeSpan.Zero,
                    ValidateLifetime = true
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
                if (user == null)
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
            existingUser.Visiblity = user.Visiblity;
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
