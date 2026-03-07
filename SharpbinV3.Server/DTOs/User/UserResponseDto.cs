namespace SharpbinV3.Server.DTOs.User
{
    public class UserSimpleDto
    {
        public int? UID { get; set; }
        public Guid UUID { get; set; }
        public long CreatedAt { get; set; }
        public string Username { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
        public int[] Roles { get; set; } = [];
        public int Visibility { get; set; }
    }

    public class UserResponseDto : UserSimpleDto
    {
        public string? Email { get; set; }
        public bool EmailVerified { get; set; } = false;
        public long? LastLogin { get; set; }
    }
}
