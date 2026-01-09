using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OtpNet;
using SharpbinV3.Server.Data;

namespace SharpbinV3.Server.Services.Verification.Providers
{
    public sealed class TotpVerificationProvider : IVerificationProvider
    {
        private readonly AppDbContext _db;
        private readonly IDataProtector _protector;
        private readonly IMemoryCache _cache;

        public TotpVerificationProvider(
            AppDbContext db,
            IDataProtectionProvider dataProtectionProvider,
            IMemoryCache cache
        )
        {
            _db = db;
            _protector = dataProtectionProvider.CreateProtector("TotpSecret-v1");
            _cache = cache;
        }

        public int Priority => 0;
        public bool IsConfigured => false;

        public async Task<bool> VerifyAsync(VerificationContext ctx)
        {
            if (ctx.UserUUID is null)
                return false;
            if (string.IsNullOrWhiteSpace(ctx.Code))
                return false;

            var userTotp = await _db.UserTotps.FirstOrDefaultAsync(t =>
                t.UserUUID == ctx.UserUUID.Value
            );
            if (userTotp is null)
                return false;

            var secret = _protector.Unprotect(userTotp.EncryptedSecret);
            if (!VerifyCode(secret, ctx.Code, out var step))
                return false;
            var key = $"totp:{ctx.UserUUID}:{step}";
            if (_cache.TryGetValue(key, out _))
                return false;
            _cache.Set(key, true, TimeSpan.FromSeconds(60));
            return true;
        }

        public byte[] GenerateSecret(int size = 20) => KeyGeneration.GenerateRandomKey(size);

        public string ToBase32(byte[] data) => Base32Encoding.ToString(data);

        public byte[] FromBase32(string base32) =>
            string.IsNullOrWhiteSpace(base32) ? [] : Base32Encoding.ToBytes(base32);

        public string BuildOtpAuthUri(
            string issuer,
            string accountName,
            string secretBase32,
            int digits = 6,
            int period = 30,
            string algorithm = "SHA1"
        )
        {
            var label = Uri.EscapeDataString($"{issuer}:{accountName}");
            var query =
                $"secret={secretBase32}&issuer={Uri.EscapeDataString(issuer)}&algorithm={algorithm}&digits={digits}&period={period}";
            return $"otpauth://totp/{label}?{query}";
        }

        public byte[] Protect(byte[] secret) => _protector.Protect(secret);

        public byte[] Unprotect(byte[] protectedSecret) => _protector.Unprotect(protectedSecret);

        public bool VerifyWithSecretBase32(
            string secretBase32,
            string code,
            int digits = 6,
            int period = 30,
            int window = 1
        )
        {
            var secret = FromBase32(secretBase32);
            return VerifyCode(secret, code, out _, digits, period, window);
        }

        private bool VerifyCode(
            byte[] secret,
            string code,
            out long matchedStep,
            int digits = 6,
            int period = 30,
            int window = 1
        )
        {
            var totp = new Totp(secret, step: period, mode: OtpHashMode.Sha1, totpSize: digits);
            return totp.VerifyTotp(
                code,
                out matchedStep,
                new VerificationWindow(previous: window, future: window)
            );
        }

        private string ComputeCode(byte[] key, long timestep, int digits) =>
            new Totp(key, totpSize: digits).ComputeTotp(DateTime.UtcNow);
    }
}
