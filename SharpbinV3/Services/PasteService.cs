using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using System.Text;

namespace SharpbinV3.Server.Services
{
    public sealed class PasteService(AppDbContext db, ICompressionService cs) : IPasteService
    {
        private readonly AppDbContext _db = db;
        private readonly ICompressionService _cs = cs;
        private readonly static string[] ValidSyntaxLanguages =
        [
            "plaintext",
            "autoHotkey",
            "autoIt",
            "bash",
            "c",
            "cpp",
            "csharp",
            "css",
            "dart",
            "html",
            "java",
            "javascript",
            "json",
            "lua",
            "markdown",
            "php",
            "python",
            "ruby",
            "rust",
            "sql",
            "swift",
            "typescript",
            "toml",
            "xml"
        ];

        public async Task<Paste> Create(User? author, string content, string title, string syntax, int visibility, long expiresAt)
        {
            var compressedData = _cs.Compress(content);
            var paste = new Paste
            {
                UUID = Guid.CreateVersion7(),
                ID = Utilities.GenerateRandomString(8),
                Title = title,
                AuthorUUID = author?.UUID ?? Guid.Empty,
                User = author,
                Content = compressedData,
                Size = compressedData.Length,
                TrueSize = Encoding.UTF8.GetByteCount(content),
                IsCompressed = compressedData.Length < Encoding.UTF8.GetByteCount(content),
                Syntax = syntax,
                Visibility = visibility,
                ExpiresAt = expiresAt,
            };
            _db.Pastes.Add(paste);
            await _db.SaveChangesAsync();
            return paste;
        }

        public async Task<bool> Delete(Paste paste)
        {
            _db.Pastes.Remove(paste);
            var result = await _db.SaveChangesAsync();
            return result > 0;
        }
        public async Task<Paste> Edit(Paste paste)
        {
            _db.Pastes.Update(paste);
            await _db.SaveChangesAsync();
            return paste;
        }
        public async Task<bool> Exists(string id)
        {
            return await _db.Pastes.AnyAsync(p => p.ID == id);
        }
        public async Task<bool> Exists(Guid uuid)
        {
            return await _db.Pastes.AnyAsync(p => p.UUID == uuid);
        }
        public async Task<bool> EditText(Paste paste, string text)
        {
            var compressedData = _cs.Compress(text);
            paste.Content = compressedData;
            paste.Size = compressedData.Length;
            paste.TrueSize = Encoding.UTF8.GetByteCount(text);
            paste.EditedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            paste.IsCompressed = compressedData.Length < Encoding.UTF8.GetByteCount(text);
            _db.Pastes.Update(paste);
            var result = await _db.SaveChangesAsync();
            return result > 0;
        }
        public async Task<Paste> Get(string id)
        {
            var paste = await _db.Pastes.Include(p => p.User).FirstOrDefaultAsync(p => p.ID == id);
            return paste ?? throw new KeyNotFoundException("Paste not found");
        }
        public async Task<List<Paste>> GetList(int offset, int count, bool publicOnly = false)
        {
            var query = _db.Pastes.AsQueryable();
            if (publicOnly)
                query = query.Where(p => p.Visibility == 0);

            return await query
                .OrderByDescending(p => p.PID)
                .Skip(offset)
                .Take(count)
                .ToListAsync();
        }

        public async Task<bool> ValidateSyntax(string syntax)
        {
            return await Task.FromResult(ValidSyntaxLanguages.Contains(syntax));
        }
        public async Task<bool> ValidateTitle(string title)
        {
            return await Task.FromResult(title.Length <= 500);
        }
        public async Task<bool> ValidateVisibility(int visibility)
        {
            return await Task.FromResult(visibility >= 0 && visibility <= 2);
        }
        public async Task<bool> ValidateExpiresAt(long expiresAt)
        {
            if (expiresAt == 0) return true;
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return await Task.FromResult(expiresAt > currentTime - 1000);
        }
    }
}
