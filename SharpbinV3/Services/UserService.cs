using Microsoft.EntityFrameworkCore;
using SharpbinV3.Data;
using SharpbinV3.Data.Entities;


namespace SharpbinV3.Services
{
    public sealed class UserService(AppDbContext db) : IUserService
    {
        private readonly AppDbContext _db = db;

        public Task<User?> GetByUID(int uid) => _db.Users.FirstOrDefaultAsync(u => u.UID == uid);
        public Task<User?> GetByUUID(Guid uuid) => _db.Users.FirstOrDefaultAsync(u => u.UUID == uuid);
        public Task<User?> GetByUsername(string username) => _db.Users.FirstOrDefaultAsync(u => u.Username == username);
        public Task<User?> GetByEmail(string email) => _db.Users.FirstOrDefaultAsync(u => u.Email == email);
    }
}
