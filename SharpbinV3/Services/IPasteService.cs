using SharpbinV3.Data.Entities;
using SharpbinV3.DTOs;

namespace SharpbinV3.Services
{
    public interface IPasteService
    {
        Task<Paste> Create(User? author, string content, string title, string syntax, int visibility, long expiresAt);
        Task<bool> Delete(Paste paste);
        Task<Paste> Edit(Paste paste);
        Task<bool> Exists(string id);
        Task<bool> Exists(Guid uuid);
        Task<bool> EditText(Paste paste, string text);
        Task<Paste> Get(string id);
        Task<List<Paste>> GetList(int offset, int count, bool publicOnly = false);
    }
}
