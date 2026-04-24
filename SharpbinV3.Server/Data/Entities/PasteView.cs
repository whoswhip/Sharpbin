using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(PastePID), nameof(ViewerHash), IsUnique = true)]
    public class PasteView
    {
        [Key]
        public int Id { get; set; }
        public long PastePID { get; set; }
        
        [MaxLength(64)]
        public string ViewerHash { get; set; } = null!;
        public long ViewedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public Paste Paste { get; set; } = null!;
    }
}
