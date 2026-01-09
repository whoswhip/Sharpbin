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

        public async Task<bool> VerifyAsync(
            VerificationContext context,
            IVerificationProvider? provider = null
        )
        {
            var activeProvider = provider ?? GetActiveProvider();

            if (activeProvider is null)
                return true;

            if (string.IsNullOrWhiteSpace(context.Token))
                return false;

            return await activeProvider.VerifyAsync(context);
        }
    }
}
