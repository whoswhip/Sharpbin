using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    public class UserTotp
    {
        [Key]
        public Guid UserUUID { get; set; }
        public byte[] EncryptedSecret { get; set; } = null!;
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public User User { get; set; } = null!;
    }
}
