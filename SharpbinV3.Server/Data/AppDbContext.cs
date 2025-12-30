using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Data
{
    public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<Paste> Pastes => Set<Paste>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    }
}
