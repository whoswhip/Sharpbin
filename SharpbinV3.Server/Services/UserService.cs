using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Services
{
    public sealed class UserService(AppDbContext db)
    {
        private readonly AppDbContext _db = db;

        public Task<User?> GetByUID(int uid, bool withPastes = false)
        {
            IQueryable<User> query = _db.Users;
            if (withPastes)
                query = query.Include(u => u.Pastes);
            return query.FirstOrDefaultAsync(u => u.UID == uid);
        }

        public Task<User?> GetByUUID(Guid uuid, bool withPastes = false)
        {
            IQueryable<User> query = _db.Users;
            if (withPastes)
                query = query.Include(u => u.Pastes);
            return query.FirstOrDefaultAsync(u => u.UUID == uuid);
        }

        public Task<User?> GetByUsername(string username, bool withPastes = false)
        {
            var normalizedUsername = NormalizeUsername(username);
            IQueryable<User> query = _db.Users;
            if (withPastes)
                query = query.Include(u => u.Pastes);
            return query.FirstOrDefaultAsync(u => u.Username == normalizedUsername);
        }

        public Task<User?> GetByEmail(string email, bool withPastes = false)
        {
            var normalizedEmail = NormalizeEmail(email);
            if (normalizedEmail == null)
                return Task.FromResult<User?>(null);

            IQueryable<User> query = _db.Users;
            if (withPastes)
                query = query.Include(u => u.Pastes);
            return query.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
        }

        public async Task<User> Update(User user)
        {
            user.Username = NormalizeUsername(user.Username);
            user.Email = NormalizeEmail(user.Email);
            _db.Users.Update(user);
            await _db.SaveChangesAsync();
            return user;
        }

        public static string NormalizeUsername(string username) => username.ToLowerInvariant();

        public static string? NormalizeEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return null;

            return email.Trim().ToLowerInvariant();
        }
    }
}
