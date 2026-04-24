using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;

namespace SharpbinV3.Server.DTOs.User
{
    public class UserSimpleDto
    {
        public long? UID { get; set; }
        public Guid UUID { get; set; }
        public long CreatedAt { get; set; }
        public string Username { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
        public Role Roles { get; set; } = Role.User;
        public bool IsBanned { get; set; } = false;
        public Visibility Visibility { get; set; }
    }

    public class UserResponseDto : UserSimpleDto
    {
        public string? Email { get; set; }
        public bool EmailVerified { get; set; } = false;
        public long? LastLogin { get; set; }
    }
}
