using SharpbinV3.Data.Entities;

namespace SharpbinV3.Services
{
    public interface IPasteService
    {
        Task<Paste> Create(Paste paste);
        Task<bool> Delete(Paste paste);
        Task<Paste> Edit(Paste paste);
        Task<bool> Exists(string id);
        Task<bool> EditText(Paste paste, string text);
        Task<Paste> Get(string id);
        Task<List<Paste>> GetList(int offset, int count);
    }
}
