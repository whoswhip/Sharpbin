using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Data
{
    public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<Paste> Pastes => Set<Paste>();
        public DbSet<PasteView> PasteViews => Set<PasteView>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
        public DbSet<UserTotp> UserTotps => Set<UserTotp>();
        public DbSet<Report> Reports => Set<Report>();
        public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
        public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Paste>()
                .HasOne(p => p.User)
                .WithMany(u => u.Pastes)
                .HasForeignKey(p => p.AuthorUUID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<PasteView>()
                .HasOne(pv => pv.Paste)
                .WithMany(p => p.PasteViews)
                .HasForeignKey(pv => pv.PastePID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RefreshToken>()
                .HasOne(r => r.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(r => r.UserUUID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(r => r.TokenHash)
                .IsUnique();


            modelBuilder.Entity<UserTotp>()
                .HasOne(t => t.User)
                .WithOne(u => u.Totp)
                .HasForeignKey<UserTotp>(t => t.UserUUID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Report>()
                .HasOne(r => r.Paste)
                .WithMany(p => p.Reports)
                .HasForeignKey(r => r.PastePID)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<Report>()
                .HasOne(r => r.User)
                .WithMany(u => u.Reports)
                .HasForeignKey(r => r.UserUUID)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<ApiKey>()
                .HasOne(a => a.User)
                .WithMany(u => u.ApiKeys)
                .HasForeignKey(a => a.UserUUID)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<EmailVerificationToken>()
                .HasOne(a => a.User)
                .WithMany(u => u.EmailVerificationTokens)
                .HasForeignKey(a => a.UserUUID)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
