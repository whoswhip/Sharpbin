using SharpbinV3.Server.Services.Verification.Providers;

namespace SharpbinV3.Server.Services.Verification
{
    public sealed class VerificationService(IEnumerable<IVerificationProvider> providers)
    {
        private readonly IReadOnlyList<IVerificationProvider> _providers = [.. providers];

        private IVerificationProvider? GetActiveProvider()
        {
            return _providers
                .Where(p => p.IsConfigured)
                .OrderByDescending(p => p.Priority)
                .FirstOrDefault();
        }

        public async Task<bool> VerifyAsync(string? token, string? ip)
        {
            var provider = GetActiveProvider();

            if (provider is null)
                return true;

            if (string.IsNullOrWhiteSpace(token))
                return false;

            return await provider.VerifyAsync(token, ip);
        }
    }

}
