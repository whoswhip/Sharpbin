namespace SharpbinV3.Server.DTOs.ApiKey
{
    public sealed class ApiKeyListItemDto
    {
        public required string Name { get; set; }
        public required Guid UUID { get; set; }
        public required long CreatedAt { get; set; }
        public long? LastUsedAt { get; set; }
    }
}
