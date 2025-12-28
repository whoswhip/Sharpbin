using SharpbinV3.Server.Data.Entities;

namespace SharpbinV3.Server.Services
{
    public interface IUserService
    {
        Task<User?> GetByUID(int uid, bool withPastes = false);
        Task<User?> GetByUsername(string username, bool withPastes = false);
        Task<User?> GetByUUID(Guid uuid, bool withPastes = false);
        Task<User?> GetByEmail(string email, bool withPastes = false);
    }
}
