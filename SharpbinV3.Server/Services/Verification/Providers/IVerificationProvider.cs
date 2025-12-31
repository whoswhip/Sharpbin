namespace SharpbinV3.Server.Services.Verification.Providers
{
    public interface IVerificationProvider
    {
        int Priority { get; }
        bool IsConfigured { get; }
        Task<bool> VerifyAsync(string token, string? ip);
    }
}
