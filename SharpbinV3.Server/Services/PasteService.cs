using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services
{
    public sealed class PasteService(
        AppDbContext db,
        ICompressionService cs,
        IMemoryCache cache,
        IOptions<PasteSettings> options
    )
    {
        private readonly AppDbContext _db = db;
        private readonly ICompressionService _cs = cs;
        private readonly IMemoryCache _cache = cache;
        private readonly PasteSettings _pasteSettings = options.Value;
        private readonly Lock _invalidationLock = new();
        private readonly HashSet<string> _pasteListCacheKeys = [];

        public async Task<Paste> Create(
            User? author,
            string content,
            string title,
            string syntax,
            int visibility,
            long expiresAt,
            bool shouldCompress
        )
        {
            var data = Encoding.UTF8.GetBytes(content);
            if (shouldCompress)
                data = _cs.Compress(content);

            var paste = new Paste
            {
                UUID = Guid.CreateVersion7(),
                ID = Utilities.GenerateRandomString(8),
                Title = title,
                AuthorUUID = author?.UUID,
                User = author,
                Content = data,
                Size = data.Length,
                TrueSize = Encoding.UTF8.GetByteCount(content),
                IsCompressed = data.Length < Encoding.UTF8.GetByteCount(content),
                Syntax = syntax,
                Visibility = visibility,
                ExpiresAt = expiresAt,
            };
            _db.Pastes.Add(paste);
            if (author != null)
            {
                author.Pastes.Add(paste);
                _db.Users.Update(author);
            }
            await _db.SaveChangesAsync();

            InvalidatePasteListCache();

            return paste;
        }

        public async Task<bool> Delete(Paste paste)
        {
            _db.Pastes.Remove(paste);
            var result = await _db.SaveChangesAsync();

            InvalidatePasteCache(paste.ID);

            return result > 0;
        }

        public async Task<Paste> Edit(Paste paste)
        {
            _db.Pastes.Update(paste);
            await _db.SaveChangesAsync();

            InvalidatePasteCache(paste.ID);

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
            var data = Encoding.UTF8.GetBytes(text);
            if (_pasteSettings.EnablePasteCompression)
                data = _cs.Compress(text);

            paste.Content = data;
            paste.Size = data.Length;
            paste.TrueSize = Encoding.UTF8.GetByteCount(text);
            paste.EditedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            paste.IsCompressed = data.Length < Encoding.UTF8.GetByteCount(text);
            _db.Pastes.Update(paste);
            var result = await _db.SaveChangesAsync();

            InvalidatePasteCache(paste.ID);

            return result > 0;
        }

        public async Task<(Paste? paste, bool alreadyExists)> RecordView(
            Paste paste,
            HttpContext context
        )
        {
            if (paste == null)
                return (null, false);
            if (context == null)
                return (null, false);
            if (_pasteSettings.View_HMAC_Secret == null)
                return (null, false);

            var viewerIp = context.GetRequestIP();
            var viewerUserAgent = context.Request.Headers.UserAgent.ToString();
            JwtUser? viewerUser = context.GetJwtUser();

            string viewerHash;
            if (viewerUser != null)
                viewerHash = Utilities.ComputeHmacSha256(
                    _pasteSettings.View_HMAC_Secret,
                    viewerUser.UUID.ToString()
                );
            else
                viewerHash = Utilities.ComputeHmacSha256(
                    _pasteSettings.View_HMAC_Secret,
                    viewerIp + viewerUserAgent
                );

            if (
                await _db.PasteViews.AnyAsync(pv =>
                    pv.PastePID == paste.PID && pv.ViewerHash == viewerHash
                )
            )
                return (null, true);

            _db.PasteViews.Add(
                new PasteView
                {
                    PastePID = paste.PID,
                    ViewerHash = viewerHash,
                    ViewedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                }
            );

            paste.Views += 1;
            _db.Pastes.Update(paste);
            var result = await _db.SaveChangesAsync();

            if (result > 0)
                InvalidatePasteCache(paste.ID);

            return (result > 0 ? paste : null, result > 0);
        }

        public async Task<Paste?> Get(string id)
        {
            string key = $"v1:paste:{id}";
            var paste = await _cache.GetOrCreateAsync(
                key,
                async entry =>
                {
                    entry.SetSlidingExpiration(TimeSpan.FromMinutes(10));
                    return await _db
                        .Pastes.Include(p => p.User)
                        .FirstOrDefaultAsync(p => p.ID == id);
                }
            );
            return paste ?? null;
        }

        public async Task<List<Paste>> GetList(int offset, int count, bool publicOnly = false)
        {
            string key = $"v1:list:pastes:public={publicOnly}:offset={offset}:count={count}";

            var pastes = await _cache.GetOrCreateAsync(
                key,
                async entry =>
                {
                    entry.SetSlidingExpiration(TimeSpan.FromMinutes(5));

                    lock (_invalidationLock)
                        _pasteListCacheKeys.Add(key);

                    var query = _db.Pastes.AsQueryable();
                    if (publicOnly)
                        query = query.Where(p => p.Visibility == 0);

                    return await query
                        .OrderByDescending(p => p.PID)
                        .Skip(offset)
                        .Take(count)
                        .Include(p => p.User)
                        .ToListAsync();
                }
            );

            return pastes ?? [];
        }

        public bool ValidateSyntax(string syntax)
        {
            return _pasteSettings.ValidSyntaxLanguages.Contains(syntax);
        }

        public bool ValidateTitle(string title)
        {
            return title.Length <= _pasteSettings.MaxTitleLength;
        }

        public bool ValidateVisibility(int visibility)
        {
            return visibility >= 0 && visibility <= 2;
        }

        public bool ValidateExpiresAt(long expiresAt)
        {
            if (expiresAt == 0)
                return true;
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return expiresAt > currentTime - 1000;
        }

        private void InvalidatePasteCache(string pasteId)
        {
            string key = $"v1:paste:{pasteId}";
            _cache.Remove(key);
        }

        private void InvalidatePasteListCache()
        {
            lock (_invalidationLock)
            {
                foreach (var listKey in _pasteListCacheKeys)
                    _cache.Remove(listKey);

                _pasteListCacheKeys.Clear();
            }
        }
    }
}
