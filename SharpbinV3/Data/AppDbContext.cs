using Microsoft.EntityFrameworkCore;
using SharpbinV3.Data.Entities;

namespace SharpbinV3.Data
{
    public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<Paste> Pastes => Set<Paste>();
    }
}
