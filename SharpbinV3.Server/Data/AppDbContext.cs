using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Data
{
    public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<Paste> Pastes => Set<Paste>();
        public DbSet<PasteInteraction> PasteInteractions => Set<PasteInteraction>();
        public DbSet<PasteView> PasteViews => Set<PasteView>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
        public DbSet<UserTotp> UserTotps => Set<UserTotp>();
        public DbSet<Report> Reports => Set<Report>();
        public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
        public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();
        public DbSet<Comment> Comments => Set<Comment>();
        public DbSet<CommentInteraction> CommentInteractions => Set<CommentInteraction>();

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

            modelBuilder.Entity<Report>()
                .HasOne<Comment>()
                .WithMany(c => c.Reports)
                .HasForeignKey(r => r.CommentID)
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

            modelBuilder.Entity<Comment>()
                .HasOne(c => c.ParentComment)
                .WithMany(c => c.Replies)
                .HasForeignKey(c => c.ParentCommentID)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<CommentInteraction>()
                .HasOne(ci => ci.Comment)
                .WithMany(c => c.Interactions)
                .HasForeignKey(ci => ci.CommentID)
                .OnDelete(DeleteBehavior.Cascade);
            
            modelBuilder.Entity<PasteInteraction>()
                .HasOne(pi => pi.Paste)
                .WithMany(p => p.Interactions)
                .HasForeignKey(pi => pi.PasteID)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
