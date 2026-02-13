using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    public sealed class ApiKey
    {
        [Key]
        public Guid UUID { get; set; } = Guid.CreateVersion7();
        public required Guid UserUUID { get; set; }
        public User? User { get; set; }
        public required string KeyHash { get; set; }
        public required string Name { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public long? LastUsedAt { get; set; }
    }
}
