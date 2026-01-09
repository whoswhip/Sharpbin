namespace SharpbinV3.Server.Services.Verification
{
    public sealed class VerificationContext
    {
        public string? Token { get; init; }
        public string? Ip { get; init; }

        public Guid? UserUUID { get; init; }
        public string? Code { get; init; }
    }
}
