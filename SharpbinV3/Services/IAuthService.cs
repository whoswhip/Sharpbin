using SharpbinV3.Data.Entities;
using SharpbinV3.DTOs;

namespace SharpbinV3.Services
{
    public interface IAuthService
    {
        Task<User> CreateUser(string username, string password, string? email, string? displayName);
        Task<JWTResult> GenerateJWTToken(User user);
        Task<bool> ValidateJWTToken(string token);
        Task<JWTResult> RefreshJWTToken(string token, string refreshToken);
    }
}
