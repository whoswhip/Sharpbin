using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;


namespace SharpbinV3.Server.Services
{
    public sealed class UserService(AppDbContext db) : IUserService
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
            IQueryable<User> query = _db.Users;
            if (withPastes)
                query = query.Include(u => u.Pastes);
            return query.FirstOrDefaultAsync(u => u.Username == username);
        }

        public Task<User?> GetByEmail(string email, bool withPastes = false)
        {
            IQueryable<User> query = _db.Users;
            if (withPastes)
                query = query.Include(u => u.Pastes);
            return query.FirstOrDefaultAsync(u => u.Email == email);
        }
    }
}
