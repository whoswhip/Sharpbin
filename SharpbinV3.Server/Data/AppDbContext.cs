using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Data
{
    public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<Paste> Pastes => Set<Paste>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
        public DbSet<UserTotp> UserTotps => Set<UserTotp>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Paste>()
                .HasOne(p => p.User)
                .WithMany(u => u.Pastes)
                .HasForeignKey(p => p.AuthorUUID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RefreshToken>()
                .HasOne(r => r.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(r => r.UserUUID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserTotp>()
                .HasOne(t => t.User)
                .WithOne(u => u.Totp)
                .HasForeignKey<UserTotp>(t => t.UserUUID)
                .OnDelete(DeleteBehavior.Cascade);
        }

    }
}
