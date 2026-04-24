using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services
{
    public sealed class PasteService(AppDbContext db, ICompressionService cs, IMemoryCache cache, IOptions<PasteSettings> options)
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
            Visibility visibility,
            long expiresAt,
            bool shouldCompress
        )
        {
            long originalSize = Encoding.UTF8.GetByteCount(content);
            var data = Encoding.UTF8.GetBytes(content);
            if (shouldCompress)
                data = _cs.Compress(content);

            double compressionRatio = (double)data.Length / originalSize;

            var paste = new Paste
            {
                UUID = Guid.CreateVersion7(),
                ID = Utilities.GenerateSecureRandomString(8),
                Title = title,
                AuthorUUID = author?.UUID,
                User = author,
                Content = compressionRatio < _pasteSettings.CompressionThreshold ? data : Encoding.UTF8.GetBytes(content),
                StoredSize = data.Length,
                OriginalSize = originalSize,
                IsCompressed = compressionRatio < _pasteSettings.CompressionThreshold,
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
            long originalSize = Encoding.UTF8.GetByteCount(text);
            var data = Encoding.UTF8.GetBytes(text);
            if (_pasteSettings.EnablePasteCompression)
                data = _cs.Compress(text);

            double compressionRatio = (double)data.Length / originalSize;

            paste.Content = compressionRatio < _pasteSettings.CompressionThreshold ? data : Encoding.UTF8.GetBytes(text);
            paste.StoredSize = data.Length;
            paste.OriginalSize = originalSize;
            paste.EditedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            paste.IsCompressed = compressionRatio < _pasteSettings.CompressionThreshold;
            _db.Pastes.Update(paste);
            var result = await _db.SaveChangesAsync();

            InvalidatePasteCache(paste.ID);

            return result > 0;
        }

        public async Task<(Paste? paste, bool alreadyExists)> RecordView(Paste paste, HttpContext context)
        {
            if (paste == null || context == null || _pasteSettings.View_HMAC_Secret == null)
                return (null, false);

            var viewerIp = context.GetRequestIP();
            var viewerUserAgent = context.Request.Headers.UserAgent.ToString();
            var viewerUser = context.GetJwtUser();

            var viewerHash =
                viewerUser != null
                    ? Utilities.ComputeHmacSha256(_pasteSettings.View_HMAC_Secret, $"user:{viewerUser.UUID}")
                    : Utilities.ComputeHmacSha256(_pasteSettings.View_HMAC_Secret, $"anon:{viewerIp}:{viewerUserAgent}");

            var view = new PasteView
            {
                PastePID = paste.PID,
                ViewerHash = viewerHash,
                ViewedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };

            _db.PasteViews.Add(view);

            try
            {
                paste.Views += 1;
                _db.Pastes.Update(paste);

                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                return (null, true);
            }

            InvalidatePasteCache(paste.ID);
            return (paste, false);
        }

        public async Task<PasteInteraction?> RecordInteraction(Paste paste, User user, Interaction type)
        {
            if (paste == null || user == null)
                return null;

            var interaction = new PasteInteraction
            {
                PasteID = paste.PID,
                UserUUID = user.UUID,
                Type = type,
            };

            _db.PasteInteractions.Add(interaction);

            try
            {
                await _db.SaveChangesAsync();
                InvalidatePasteCache(paste.ID);
                return interaction;
            }
            catch (DbUpdateException)
            {
                return null;
            }
        }

        public async Task<bool> RemoveInteraction(Paste paste, User user)
        {
            if (paste == null || user == null)
                return false;

            var interaction = await _db.PasteInteractions.FirstOrDefaultAsync(pi => pi.PasteID == paste.PID && pi.UserUUID == user.UUID);
            if (interaction == null)
                return false;

            _db.PasteInteractions.Remove(interaction);
            await _db.SaveChangesAsync();
            InvalidatePasteCache(paste.ID);
            return true;
        }

        public async Task<Paste?> Get(string id)
        {
            string key = $"v1:paste:{id}";
            var paste = await _cache.GetOrCreateAsync(
                key,
                async entry =>
                {
                    entry.SetSlidingExpiration(TimeSpan.FromMinutes(10));
                    var _paste = await _db.Pastes.AsNoTracking().Include(p => p.User).FirstOrDefaultAsync(p => p.ID == id);
                    if (_paste != null)
                    {
                        _paste.PositiveInteractionCount = await _db
                            .PasteInteractions.Where(pi => pi.PasteID == _paste.PID && pi.Type == Interaction.Positive)
                            .CountAsync();
                        _paste.NegativeInteractionCount = await _db
                            .PasteInteractions.Where(pi => pi.PasteID == _paste.PID && pi.Type == Interaction.Negative)
                            .CountAsync();
                    }
                    return _paste;
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

                    return await query.OrderByDescending(p => p.PID).Skip(offset).Take(count).Include(p => p.User).ToListAsync();
                }
            );

            return pastes ?? [];
        }

        public async Task<PasteInteraction?> GetUserInteraction(Paste paste, Guid userUUID)
        {
            if (paste == null)
                return null;

            return await _db.PasteInteractions.FirstOrDefaultAsync(pi => pi.PasteID == paste.PID && pi.UserUUID == userUUID);
        }

        public bool ValidateSyntax(string syntax)
        {
            return _pasteSettings.ValidSyntaxLanguages.Contains(syntax);
        }

        public bool ValidateTitle(string title)
        {
            return title.Length <= _pasteSettings.MaxTitleLength;
        }

        public bool ValidateVisibility(Visibility visibility)
        {
            return Enum.IsDefined(visibility);
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
