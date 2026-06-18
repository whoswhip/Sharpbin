using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services
{
    public sealed class ApiKeyService(AppDbContext db, IOptions<AuthSettings> authOptions)
    {
        private readonly AppDbContext _db = db;
        private readonly AuthSettings _authSettings = authOptions.Value;

        public const int KeyLength = 64;

        private string ComputeHash(string input)
        {
            if (string.IsNullOrEmpty(_authSettings.API_Key_HMAC_Secret))
                return Utilities.ComputeSha256(input);
            else
                return Utilities.ComputeHmacSha256(_authSettings.API_Key_HMAC_Secret, input);
        }

        public async Task<ApiKey?> GetByKeyAsync(string key)
        {
            var keyHash = ComputeHash(key);
            return await _db.ApiKeys.Include(a => a.User).FirstOrDefaultAsync(a => a.KeyHash == keyHash);
        }

        public async Task<(ApiKey apiKey, string key)> CreateAsync(Guid userUUID, string name)
        {
            var key = Utilities.GenerateSecureRandomString(KeyLength);
            var keyHash = ComputeHash(key);

            var apiKey = new ApiKey
            {
                UserUUID = userUUID,
                Name = name,
                KeyHash = keyHash,
            };

            _db.ApiKeys.Add(apiKey);
            await _db.SaveChangesAsync();

            return (apiKey, key);
        }

        public async Task<bool> DeleteAsync(Guid userUUID, Guid keyUUID)
        {
            var apiKey = await _db.ApiKeys.FirstOrDefaultAsync(a => a.UUID == keyUUID && a.UserUUID == userUUID);
            if (apiKey == null)
                return false;

            _db.ApiKeys.Remove(apiKey);
            await _db.SaveChangesAsync();
            return true;
        }

        public async Task<List<ApiKey>> GetUserKeysAsync(Guid userUUID)
        {
            return await _db.ApiKeys.Where(a => a.UserUUID == userUUID).OrderByDescending(a => a.CreatedAt).ToListAsync();
        }

        public async Task UpdateLastUsedAsync(Guid keyUUID)
        {
            var apiKey = await _db.ApiKeys.FirstOrDefaultAsync(a => a.UUID == keyUUID);
            if (apiKey == null)
                return;

            apiKey.LastUsedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await _db.SaveChangesAsync();
        }
    }
}
