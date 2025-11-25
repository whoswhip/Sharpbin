using SharpbinV3.Data.Entities;

namespace SharpbinV3.Services
{
    public interface IUserService
    {
        Task<User?> GetByUID(int uid);
        Task<User?> GetByUsername(string username);
        Task<User?> GetByUUID(Guid uuid);
        Task<User?> GetByEmail(string email);
    }
}
