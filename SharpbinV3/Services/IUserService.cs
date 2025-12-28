using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Services
{
    public interface IUserService
    {
        Task<User?> GetByUID(int uid);
        Task<User?> GetByUsername(string username);
        Task<User?> GetByUUID(Guid uuid);
        Task<User?> GetByEmail(string email);
    }
}
