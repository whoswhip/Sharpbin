using Microsoft.EntityFrameworkCore;
using SharpbinV3.Data;
using SharpbinV3.Data.Entities;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV3.Services
{
    public sealed class UserService(AppDbContext db) : IUserService
    {
        private readonly AppDbContext _db = db;

        public Task<User?> GetByUID(int uid) => _db.Users.FirstOrDefaultAsync(u => u.UID == uid);
        public Task<User?> GetByUUID(Guid uuid) => _db.Users.FirstOrDefaultAsync(u => u.UUID == uuid);
        public Task<User?> GetByUsername(string username) => _db.Users.FirstOrDefaultAsync(u => u.Username == username);
        public Task<User?> GetByEmail(string email) => _db.Users.FirstOrDefaultAsync(u => u.Email == email);

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
    }
}
