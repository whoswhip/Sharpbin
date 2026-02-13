namespace SharpbinV3.Server.DTOs.ApiKey
{
    public sealed class ApiKeyResponseDto
    {
        public required string Key { get; set; }
        public required string Name { get; set; }
        public required Guid UUID { get; set; }
        public required long CreatedAt { get; set; }
    }
}
